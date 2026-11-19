//! 代理管理：手动地址 CRUD、Clash Verge 端点同步、启停与连通性测试。
//! 写操作返回最新代理列表，测试失败以 `success:false` 返回 200。

use crate::server::core::sub_kernel;
use crate::server::core::proxies::ResolvedProxy;
static SUB_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
use axum::body::Bytes;
use axum::response::Response;
use serde_json::{json, Value};

use crate::server::core::egress;
use crate::server::core::proxies::normalize_account_proxy;
use crate::server::core::{proxy_pool, proxy_settings};
use crate::server::errors::management_error;
use crate::server::http::{ok_json, parse_body};
use crate::server::logging;
use crate::server::ServerState;

use super::accounts::proxy_error;

pub async fn list_proxies(state: &ServerState) -> Response {
    let snapshot = state.store().list_accounts();
    let accounts: Vec<Value> = snapshot.get("accounts").and_then(Value::as_array)
        .map(|items| items.iter().map(|account| json!({
            "id": account.get("id"),
            "name": account.get("displayName").filter(|value| value.as_str().is_some_and(|text| !text.is_empty()))
                .or_else(|| account.get("name")),
            "priority": account.get("priority"),
            "enabled": account.get("enabled"),
            "proxy": account.get("proxy"),
        })).collect()).unwrap_or_default();
    ok_json(json!({
        "accounts": accounts,
        "clash": crate::server::core::proxies::clash_proxy_options(),
        "note": "支持手动 HTTP / SOCKS5 地址与 Clash Verge 端点；未配置代理时直连",
    }))
}

pub async fn system_proxy() -> Response {
    let mut response = match tokio::task::spawn_blocking(crate::server::core::proxies::system::snapshot).await {
        Ok(Ok(value)) => ok_json(value),
        Ok(Err(message)) => management_error(400, message),
        Err(_) => management_error(500, "读取系统代理失败"),
    };
    response.headers_mut().insert("cache-control", axum::http::HeaderValue::from_static("no-store"));
    response
}

pub async fn test_proxy(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_body(body) {
        Ok(value) => value,
        Err(_) => return management_error(400, "请求内容不是有效 JSON"),
    };
    let mut proxy = None;
    if let Some(id) = payload.get("id").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        let Some(creds) = state.store().get_credentials_by_id(id) else {
            return management_error(404, "账号不存在");
        };
        if let Some(error) = creds.proxy_error {
            return management_error(400, error);
        }
        match crate::server::core::proxies::ResolvedProxy::from_json(&creds.proxy) {
            Ok(resolved) => proxy = resolved,
            Err(reason) => return management_error(400, reason),
        }
    } else if let Some(config_value) = payload.get("proxy") {
        let config = match normalize_account_proxy(config_value) {
            Ok(value) => value,
            Err(error) => return proxy_error(error),
        };
        if let Some(config) = config {
            if let Some(resolution) = crate::server::core::proxies::resolve_account_proxy(Some(&config)) {
                if let Some(error) = resolution.error() {
                    return management_error(400, error);
                }
                proxy = resolution.resolved().cloned();
            }
        }
    }
    let result = egress::test_proxy(proxy.as_ref()).await;
    logging::log("[Accounts]", &format!("代理测试{}: {}",
        proxy.as_ref().map(|proxy| format!("（{}）", proxy.label)).unwrap_or_else(|| "（直连）".to_string()),
        if result.success { format!("✅ 出口 IP {}", result.ip) } else { format!("❌ {}", result.error.clone().unwrap_or_default()) },
    ));
    let mut data = result.to_json();
    data["proxy"] = egress::describe_public(proxy.as_ref());
    ok_json(data)
}

fn pool_references(state: &ServerState) -> std::collections::HashMap<String, Vec<Value>> {
    let mut references: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
    let snapshot = state.store().list_accounts();
    let Some(accounts) = snapshot.get("accounts").and_then(Value::as_array) else {
        return references;
    };
    for account in accounts {
        let Some(config) = account.get("proxy").and_then(|proxy| proxy.get("config")) else { continue };
        let ids: Vec<String> = if crate::server::core::proxies::is_rotate_config(config) {
            crate::server::core::proxy_rotate::candidate_ids(config)
        } else {
            proxy_pool::usage::pool_reference_id(config).map(|id| vec![id.to_string()]).unwrap_or_default()
        };
        let entry = json!({
            "id": account.get("id"),
            "name": account.get("displayName").filter(|value| value.as_str().is_some_and(|text| !text.is_empty()))
                .or_else(|| account.get("name")),
            "enabled": account.get("enabled").cloned().unwrap_or(Value::Bool(true)),
        });
        for id in ids {
            references.entry(id).or_default().push(entry.clone());
        }
    }
    references
}

fn pool_payload(state: &ServerState) -> Value {
    let references = pool_references(state);
    let service_references = proxy_pool::usage::service_references();
    let live_subscriptions = crate::server::core::subscriptions::live_ids().ok();
    let items: Vec<Value> = proxy_pool::list().into_iter().map(|mut item| {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("");
        let used = references.get(id).cloned().unwrap_or_default();
        let services: Vec<Value> = service_references.iter().filter(|(_, proxy_id)| id == proxy_id)
            .map(|(service, _)| Value::String((*service).to_string())).collect();
        item["usedBy"] = json!(used);
        item["usedByServices"] = json!(services);
        item["orphan"] = json!(item["source"] == "subscription"
            && item.get("providerId").and_then(Value::as_str)
                .is_some_and(|id| live_subscriptions.as_ref()
                    .is_some_and(|ids| !ids.contains(id))));
        item
    }).collect();
    json!({ "items": items, "clash": crate::server::core::proxies::clash_proxy_options(), "kernelInstalled": sub_kernel::installed() })
}

pub async fn pool_list(state: &ServerState) -> Response {
    let _ = proxy_pool::sync_clash(false);
    ok_json(pool_payload(state))
}

pub async fn pool_sync_clash(state: &ServerState) -> Response {
    let report = proxy_pool::sync_clash(true);
    let mut data = pool_payload(state);
    data["changes"] = json!(report.changes);
    data["syncError"] = json!(report.error);
    ok_json(data)
}

pub async fn pool_create(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_body(body) {
        Ok(value) => value,
        Err(_) => return management_error(400, "请求内容不是有效 JSON"),
    };
    if payload.get("items").is_some() {
        return match proxy_pool::create_batch(&payload) {
            Ok(report) => {
                let mut data = pool_payload(state);
                data["imported"] = report;
                ok_json(data)
            }
            Err(message) => management_error(400, message),
        };
    }
    match proxy_pool::create(&payload) {
        Ok(_) => ok_json(pool_payload(state)),
        Err(message) => management_error(400, message),
    }
}

pub async fn pool_update(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_body(body) {
        Ok(value) => value,
        Err(_) => return management_error(400, "请求内容不是有效 JSON"),
    };
    match proxy_pool::update(&payload) {
        Ok(_) => ok_json(pool_payload(state)),
        Err(message) => management_error(400, message),
    }
}

pub async fn pool_remove(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_body(body) {
        Ok(value) => value,
        Err(_) => return management_error(400, "请求内容不是有效 JSON"),
    };
    let id = payload.get("id").and_then(Value::as_str).unwrap_or("");
    if id.trim().is_empty() {
        return management_error(400, "缺少代理 id");
    }
    let items = proxy_pool::list();
    let target = items.iter().find(|item| item.get("id").and_then(Value::as_str) == Some(id));
    let exists = target.is_some();
    let orphan = target
        .filter(|item| item["source"] == "subscription")
        .and_then(|item| item.get("providerId").and_then(Value::as_str))
        .is_some_and(|provider_id| crate::server::core::subscriptions::live_ids()
            .is_ok_and(|ids| !ids.contains(provider_id)));
    let result = if orphan {
        proxy_pool::remove_subscription_orphan(id).map(|(_, name)| name)
    } else {
        proxy_pool::remove(id)
    };
    match result {
        Ok(name) => {
            let mut data = pool_payload(state);
            data["removed"] = json!(name);
            ok_json(data)
        }
        Err(message) => management_error(if exists { 400 } else { 404 }, message),
    }
}

pub async fn pool_enable(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_body(body) {
        Ok(value) => value,
        Err(_) => return management_error(400, "请求内容不是有效 JSON"),
    };
    let id = payload.get("id").and_then(Value::as_str).unwrap_or("");
    if id.trim().is_empty() {
        return management_error(400, "缺少代理 id");
    }
    // 缺 enabled 就报错而不是猜：这条接口只有一个语义，猜错方向等于把用户
    // 按下的开关反过来执行
    let Some(enabled) = payload.get("enabled").and_then(Value::as_bool) else {
        return management_error(400, "缺少 enabled（true / false）");
    };
    let change = match proxy_pool::set_enabled(id, enabled) {
        Ok(value) => value,
        Err(message) => return management_error(400, message),
    };
    let listener = listener_flow(state, id, &change);
    let mut data = pool_payload(state);
    if let Some(object) = data.as_object_mut() {
        object.insert("name".to_string(), Value::String(change.name));
        object.insert("enabled".to_string(), Value::Bool(change.enabled));
        object.insert("listener".to_string(), Value::String(listener.to_string()));
    }
    ok_json(data)
}

pub async fn pool_test(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_body(body) {
        Ok(value) => value,
        Err(_) => return management_error(400, "请求内容不是有效 JSON"),
    };
    let id = payload.get("id").and_then(Value::as_str).unwrap_or("");
    let target = match proxy_pool::test_target(id) {
        Ok(target) => target,
        Err(message) => return management_error(400, message),
    };
    let test_url = match one_time_test_url(&payload) {
        Ok(value) => value,
        Err(message) => return management_error(400, message),
    };
    if let Some(url) = test_url {
        // A site probe is separate from the UI's default proxy test. Do not
        // overwrite lastTest or return the whole pool (including credentials).
        // Bound lock acquisition, listener selection and HTTPS together.
        let result = tokio::time::timeout(std::time::Duration::from_secs(8), async {
            let _guard = if target.source == "subscription" {
                Some(SUB_TEST_LOCK.lock().await)
            } else { None };
            let proxy = if target.source == "subscription" {
                let port = sub_kernel::runtime::select_test_node(&target.provider_id, &target.node).await?;
                ResolvedProxy { source: "pool".into(), protocol: "http".into(), host: "127.0.0.1".into(),
                    port: Some(port), username: String::new(), password: String::new(),
                    label: target.name.clone(), non_direct: false }
            } else { proxy_pool::resolve_for_test(id)? };
            Ok::<_, String>(egress::test_site_connectivity(Some(&proxy), 8_000, &url).await.to_json())
        }).await;
        let data = match result {
            Ok(Ok(data)) => data,
            Ok(Err(_)) => json!({ "success": false, "error": "proxy_unavailable", "durationMs": 0 }),
            Err(_) => json!({ "success": false, "error": "probe_timeout", "durationMs": 8_000 }),
        };
        // Management-envelope success is distinct from target HTTP success.
        return ok_json(json!({ "success": true, "data": data }));
    }
    // 出口解析 + 测试按来源分两条路：
    //   · subscription → 统一测试口（切组到目标节点，从测试口发测试）；
    //   · manual / clash → 原有解析（manual 用它自己的地址；clash 实时读
    //     Clash 配置），与内核无关。
    // Err 都是一句可读的中文 → 400（条目不存在 / 内核没装 / 节点已不在订阅里）。
    // 订阅分支**全程持锁**：从切组到拿到测试结果，组不能被另一条测试切走
    // （锁只在订阅分支内拿，manual / clash 不碰内核、不排队）。
    let (result, public) = if target.source == "subscription" {
        let _guard = SUB_TEST_LOCK.lock().await;
        let proxy = match sub_kernel::runtime::select_test_node(&target.provider_id, &target.node)
            .await
        {
            Ok(port) => ResolvedProxy {
                source: "pool".to_string(),
                protocol: "http".to_string(),
                host: "127.0.0.1".to_string(),
                port: Some(port),
                username: String::new(),
                password: String::new(),
                label: target.name.clone(),
                non_direct: false,
            },
            Err(message) => return management_error(400, message),
        };
        let result = egress::test_proxy(Some(&proxy)).await;
        (result, egress::describe_public(Some(&proxy)))
    } else {
        let proxy = match proxy_pool::resolve_for_test(id) {
            Ok(proxy) => proxy,
            Err(message) => return management_error(400, message),
        };
        let result = egress::test_proxy(Some(&proxy)).await;
        (result, egress::describe_public(Some(&proxy)))
    };
    let write_error = proxy_pool::record_test(
        id,
        &proxy_pool::TestOutcome {
            success: result.success,
            ip: result.ip.clone(),
            duration_ms: result.duration_ms,
            error: result.error.clone(),
        },
    )
    .err();
    logging::log(
        "[Proxies]",
        &format!(
            "代理测试（{}）: {}",
            target.name,
            if result.success {
                format!("✅ 出口 IP {}", result.ip)
            } else {
                format!("❌ {}", result.error.clone().unwrap_or_default())
            }
        ),
    );
    let mut data = result.to_json();
    if let Some(object) = data.as_object_mut() {
        object.insert("proxy".to_string(), public);
        // 结果落库失败不该把「测试已经跑完」这个事实吞掉：测试结论照常返回，
        // 界面额外提示一句「没能记住这次结果」即可
        if let Some(error) = write_error {
            object.insert("saveError".to_string(), Value::String(error));
        }
        object.insert(
            "items".to_string(),
            pool_payload(state).get("items").cloned().unwrap_or_else(|| json!([])),
        );
    }
    ok_json(data)
}

fn one_time_test_url(payload: &Value) -> Result<Option<String>, &'static str> {
    let Some(value) = payload.get("testUrl") else { return Ok(None); };
    let text = value.as_str().ok_or("testUrl 必须是 HTTP/HTTPS 网址")?.trim();
    if text.is_empty() || text.len() > 2048 { return Err("testUrl 为空或过长"); }
    let url = url::Url::parse(text).map_err(|_| "testUrl 必须是 HTTP/HTTPS 网址")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("testUrl 必须是无凭证的 HTTP/HTTPS 网址");
    }
    Ok(Some(url.to_string()))
}

#[cfg(test)]
mod site_probe_tests {
    use super::one_time_test_url;
    use serde_json::json;

    #[test]
    fn site_probe_url_is_optional_and_does_not_accept_embedded_credentials() {
        assert_eq!(one_time_test_url(&json!({})).unwrap(), None);
        assert_eq!(one_time_test_url(&json!({"testUrl":"https://example.com/health"})).unwrap(),
            Some("https://example.com/health".to_string()));
        for value in [json!(null), json!(7), json!(""), json!("file:///etc/passwd"),
            json!("https://user:secret@example.com/"), json!("https://example.com/#secret")] {
            assert!(one_time_test_url(&json!({"testUrl":value})).is_err());
        }
    }
}

pub async fn settings_get() -> Response {
    ok_json(proxy_settings::get())
}

pub async fn settings_save(body: &Bytes) -> Response {
    let payload = match parse_body(body) {
        Ok(value) => value,
        Err(_) => return management_error(400, "请求内容不是有效 JSON"),
    };
    match proxy_settings::save(&payload) {
        Ok(value) => ok_json(value),
        Err(message) => management_error(400, message),
    }
}

fn listener_flow(state: &ServerState, id: &str, change: &proxy_pool::EnabledChange) -> &'static str {
    if change.source != "subscription" {
        return "none";
    }
    if change.enabled {
        // 内核没装：补建无从谈起（地址列会提示「去订阅管理下载内核」），
        // 这里报 opening 只会让前端白轮询十几秒
        if !sub_kernel::installed() {
            return "none";
        }
        let pool_ids = proxy_pool::usage::referenced_pool_ids(Some(state.store()));
        let borrowed: std::collections::HashSet<&str> =
            pool_ids.iter().map(String::as_str).collect();
        if !proxy_pool::needs_listener(id, &borrowed) {
            return "none";
        }
        // 对账（补建方向）。返回 false 只有两种情况：这条其实没缺口（上面
        // 已挡）/ 手动关闭闩置位（对账记了日志，「启动内核」时按 wanted
        // 一并补上）—— 都不该报 opening 让前端白轮询
        if reconcile_listeners(state) {
            "opening"
        } else {
            "none"
        }
    } else {
        // 禁用：对账（回收方向）—— 缺口判据是 reconcile 的 stale 检测
        // （不在 wanted 里却还挂着端口：刚禁用的这条、先前遗留的、
        // 失去引用的都算），内核没装则无端口可收
        if !sub_kernel::installed() {
            return "none";
        }
        if reconcile_listeners(state) {
            "closing"
        } else {
            "none"
        }
    }
}
pub fn reconcile_listeners(state: &ServerState) -> bool {
    if !sub_kernel::installed() {
        return false;
    }
    let pool_ids = proxy_pool::usage::referenced_pool_ids(Some(state.store()));
    let borrowed: std::collections::HashSet<&str> =
        pool_ids.iter().map(String::as_str).collect();
    let wanted = proxy_pool::listener_node_keys(&borrowed);
    let mut missing = 0usize;
    let mut stale = 0usize;
    for (provider_id, node, port) in proxy_pool::subscription_entries_with_ports() {
        // key 形态与 `listener_node_keys` 的构造处一致（`{providerId}::{node}`）
        match (wanted.contains(&format!("{provider_id}::{node}")), port) {
            (true, None) => missing += 1,
            (false, Some(_)) => stale += 1,
            _ => {}
        }
    }
    if missing == 0 && stale == 0 {
        return false;
    }
    // 手动关闭闩：用户刚点过「关闭内核」，这里不悄悄把它带起来 —— 缺口
    // 记在这条日志里，「启动内核」重建配置时按最新引用一并收敛
    if sub_kernel::is_manually_halted() {
        logging::log(
            "[Proxies]",
            &format!(
                "内核已手动关闭 —— 监听器对账暂缓（{missing} 个待补建 / {stale} 个待回收），「启动内核」时按最新引用重算"
            ),
        );
        return false;
    }
    // 有缺口才重启内核（重建配置把缺的建出来、多的收掉）。内核未安装时投
    // 命令也无害（restart 早退在「未安装」上，见 `sub_kernel` worker 的说明）。
    sub_kernel::request_restart(crate::server::core::subscriptions::enabled_provider_inputs());
    logging::log(
        "[Proxies]",
        &format!("🔄 监听器对账：{missing} 个待补建 / {stale} 个待回收，已请求内核重建"),
    );
    true
}
