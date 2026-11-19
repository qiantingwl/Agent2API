//! Authenticated receipt of completed external maintenance. Never calls a provider or query queue.
use axum::{extract::State, response::Response, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use crate::server::{ServerState, logging, http::ok_json};
use crate::server::core::{blocking, usage_records, usage_query};
use crate::server::core::account_store::{sql, plugin_accounts::secret_of};
use super::maintenance::error_response;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    account: String,
    provider: String,
    action: String,
    request_id: String,
    observed_at: i64,
    expect: Value,
    usage: Option<Value>,
    secret: Option<Value>,
    confirmed: Option<bool>,
}

pub async fn inflight(State(state): State<ServerState>) -> Response {
    ok_json(json!({"at": logging::now_ms(), "counts": state.upstream().connections().snapshot()}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseRequest { account: String, provider: String, owner: String, release: Option<bool> }

pub async fn lease(State(state): State<ServerState>, Json(body): Json<LeaseRequest>) -> Response {
    use crate::server::core::external_lease;
    if !external_lease::supported(&body.provider) || body.owner.len() < 16 || body.owner.len() > 160 {
        return error_response(400, "Invalid lease request");
    }
    let provider = blocking::run({ let store = state.store().clone(); let account = body.account.clone();
        move || store.account_provider_of(&account) }).await;
    if provider.ok().flatten().as_deref() != Some(&body.provider) { return error_response(404, "Account/provider mismatch"); }
    if body.release == Some(true) {
        return ok_json(json!({"released": external_lease::release(&body.account, &body.owner)}));
    }
    if !external_lease::acquire(&body.account, &body.owner) { return error_response(423, "Account busy; retry without refreshing"); }
    ok_json(json!({"acquired": true, "expiresIn": 180}))
}

pub async fn apply(State(state): State<ServerState>, Json(body): Json<Receipt>) -> Response {
    let now = logging::now_ms();
    if !matches!(body.provider.as_str(), "loomy" | "raccoon" | "codearts" | "wps-lingxi")
        || !matches!(body.action.as_str(), "balance" | "credential" | "checkin")
        || body.request_id.is_empty() || body.request_id.len() > 160
        || body.observed_at <= 0 || body.observed_at > now + 30_000 || !body.expect.is_object()
    { return error_response(400, "Invalid maintenance receipt"); }
    let result = blocking::run(move || -> Result<Value, (u16, &'static str)> {
        let store = state.store();
        if body.action == "credential" {
            if store.account_provider_of(&body.account).as_deref() != Some(&body.provider) {
                return Err((404, "Account/provider mismatch"));
            }
            let secret = body.secret.as_ref().filter(|s| s.is_object()).ok_or((400, "Missing new credential"))?;
            // Retried delivery after a lost acknowledgement is a no-op.
            if store.plugin_account(&body.account).as_ref().and_then(|a| a.get("secret")) == Some(secret) {
                return Ok(json!({"applied": true, "duplicate": true}));
            }
            return match store.plugin_update_secret(&body.account, &body.expect, secret) {
                Ok(true) => Ok(json!({"applied": true})),
                Ok(false) => Err((409, "Credential changed; receipt rejected")),
                Err(_) => Err((503, "Credential storage unavailable")),
            };
        }
        let guard = store.guard();
        let record = store.record_by_id(&guard, &body.account).ok_or((404, "Account missing"))?;
        if record.provider() != body.provider { return Err((409, "Provider changed")); }
        if secret_of(&record) != body.expect { return Err((409, "Credential changed; receipt rejected")); }
        if body.action == "balance" {
            let usage = body.usage.filter(Value::is_object).ok_or((400, "Missing usage observation"))?;
            if !valid_usage_observation(&usage) {
                return Err((400, "Invalid usage observation; previous balance preserved"));
            }
            let saved = usage_records::load(&body.account);
            let duplicate = saved.query_request_id == body.request_id;
            if !duplicate && saved.last_attempt_at >= body.observed_at { return Err((409, "Newer observation already present")); }
            let key = usage_query::config::reading_key(&record);
            let authenticated_usage = usage.get("available").and_then(Value::as_f64).is_some_and(f64::is_finite)
                || usage.get("unlimited").and_then(Value::as_bool) == Some(true);
            let funded = funded_usage(&usage);
            let outcome = usage_records::UsageOutcome { usage: Some(usage), error: None, code: None, diagnostics: None };
            if !duplicate && !usage_records::write_result_at(&body.account, &outcome, &key, &body.request_id, body.observed_at) {
                return Err((503, "Observation storage unavailable or superseded"));
            }
            // A failed/old observation cannot clear a newer login failure. Do not
            // call set_needs_relogin here: it would reacquire the held store guard.
            if authenticated_usage && clearable_login_proof(&body.provider, record.get("needsRelogin").and_then(Value::as_bool) == Some(true), record.updated_at(), body.observed_at) {
                let mut restored = record.clone();
                restored.remove("needsRelogin");
                restored.remove("needsReloginReason");
                restored.set_updated_at(now);
                store.with_conn(&guard, |conn| sql::update_in_place(conn, &restored))
                    .map_err(|_| (503, "Login state update unavailable"))?;
            }
            if body.provider == "loomy" && funded && record.get("upstreamBlockedReason").and_then(Value::as_str) == Some("余额待核验：上游返回402")
                && body.observed_at > record.updated_at() {
                let mut verified = store.record_by_id(&guard, &body.account).ok_or((404, "Account missing"))?;
                verified.remove("upstreamCooldownUntil");
                verified.remove("upstreamBlockedReason");
                verified.set_updated_at(now);
                store.with_conn(&guard, |conn| sql::update_in_place(conn, &verified))
                    .map_err(|_| (503, "Balance verification state unavailable"))?;
            }
            return Ok(json!({"applied": true, "duplicate": duplicate}));
        } else {
            if body.confirmed != Some(true) { return Err((400, "Check-in requires upstream confirmation")); }
            // The receipt and check-in history commit together; replay cannot create duplicate history.
            store.with_conn_mut(&guard, |conn| {
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let Some(mut fresh) = sql::load_by_id(&tx, &body.account)? else { return Err(rusqlite::Error::InvalidQuery) };
                if secret_of(&fresh) != body.expect { return Err(rusqlite::Error::InvalidQuery); }
                let previous = fresh.get("checkinAt").and_then(Value::as_i64).unwrap_or(0);
                if previous >= body.observed_at { return Ok(()); }
                fresh.set_checkin_at(body.observed_at);
                sql::update_in_place(&tx, &fresh)?;
                tx.execute("INSERT INTO checkin_records(ts,date,source,reason,account_id,account_name,provider,outcome,ok,message,error,kept_active) VALUES(?1,date(?1/1000,'unixepoch','+8 hours'),'external-maintenance','upstream confirmed',?2,?3,?4,'success',1,'Confirmed by independent controller',NULL,0)", rusqlite::params![body.observed_at,body.account,fresh.name(),body.provider])?;
                tx.commit()
            }).map_err(|_| (503, "Check-in storage unavailable or credential conflict"))?;
        }
        Ok(json!({"applied": true}))
    }).await;
    match result {
        Ok(Ok(value)) => ok_json(value),
        Ok(Err((code, message))) => error_response(code, message),
        Err(_) => error_response(503, "Maintenance receipt unavailable"),
    }
}


fn valid_usage_observation(usage: &Value) -> bool {
    usage.get("unlimited").and_then(Value::as_bool) == Some(true)
        || usage.get("available").and_then(Value::as_f64)
            .is_some_and(f64::is_finite)
}

fn funded_usage(usage: &Value) -> bool {
    usage.get("unlimited").and_then(Value::as_bool) == Some(true)
        || usage.get("available").and_then(Value::as_f64).is_some_and(|amount| amount.is_finite() && amount > 0.0)
}

fn clearable_login_proof(provider: &str, flagged: bool, changed_at: i64, observed_at: i64) -> bool {
    matches!(provider, "loomy" | "raccoon") && flagged && observed_at > changed_at
}

#[cfg(test)]
mod closure_tests {
    use super::*;
    #[test]
    fn missing_or_invalid_balance_is_not_a_successful_observation() {
        for usage in [json!({}), json!({"available":null}), json!({"available":true}),
            json!({"available":"10"})] {
            assert!(!valid_usage_observation(&usage));
        }
        assert!(valid_usage_observation(&json!({"available":0})));
        // A genuine debt is a valid observation, but cannot release a 402 gate.
        assert!(valid_usage_observation(&json!({"available":-1})));
        assert!(!funded_usage(&json!({"available":-1})));
        assert!(valid_usage_observation(&json!({"available":1.5})));
        assert!(valid_usage_observation(&json!({"unlimited":true})));
    }
    #[test]
    fn only_spendable_balance_releases_a_402() {
        assert!(!funded_usage(&json!({"available":0})));
        assert!(!funded_usage(&json!({"available":-1})));
        assert!(funded_usage(&json!({"available":0.5})));
        assert!(funded_usage(&json!({"unlimited":true})));
    }
    #[test]
    fn newer_balance_clears_only_older_loomy_flag() {
        assert!(clearable_login_proof("loomy", true, 10, 20));
        assert!(clearable_login_proof("raccoon", true, 10, 20));
        assert!(!clearable_login_proof("raccoon", true, 20, 10));
        assert!(!clearable_login_proof("loomy", true, 20, 10));
        assert!(!clearable_login_proof("loomy", true, 20, 20));
        assert!(!clearable_login_proof("codearts", true, 10, 20));
        assert!(!clearable_login_proof("loomy", false, 10, 20));
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WpsRecheck { account: String, model: String, expect: Value }

/// Dedicated model proof. Never uses/replays customer prompts or refreshes models.
pub async fn wps_recheck(State(state): State<ServerState>, Json(body): Json<WpsRecheck>) -> Response {
    if body.model.trim().is_empty() || body.model.len() > 160 || !body.expect.is_object() {
        return error_response(400, "Invalid WPS recheck");
    }
    let record = blocking::run({let store=state.store().clone();let id=body.account.clone();
        move || {let guard=store.guard();store.record_by_id(&guard,&id)}}).await;
    let Ok(Some(record)) = record else {return error_response(404,"Account missing")};
    if record.provider() != "wps-lingxi" || record.get("enabled").and_then(Value::as_bool) == Some(false) {
        return error_response(409,"WPS account unavailable");
    }
    if secret_of(&record) != body.expect {return error_response(409,"Credential changed")}
    let adapter=crate::server::core::providers::adapter::adapter_by_id_ready("wps-lingxi").await;
    let Ok(Some(adapter))=adapter else {return error_response(503,"WPS plugin unavailable")};
    match adapter.admin_action(state.store(), &body.account, "wps.recheck", &json!({"model":body.model,"expect":body.expect})).await {
        Ok(value)=>ok_json(value), Err(_)=>error_response(503,"WPS answer proof failed; gate retained"),
    }
}
