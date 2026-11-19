"""Private JSON-pipe adapter for MiraiHub v1.1.1 (inspected 2026-11-09).

Host invocation after deployment by the parent:
    docker exec -i miraihub python -B /tmp/mirai_bridge.py
Send ONE JSON object on stdin; read ONE JSON object from stdout. No HTTP
listener, shell, Docker socket, startup migration, invitation or onboarding.
The host HMAC transport authenticates requests; this module trusts its private
pipe. Never log inventory responses: ONLY inventory contains credentials.

Contract (times are Unix milliseconds; unknown timestamps are zero):
 inventory -> {ok,items,accounts,capabilities}; items == accounts.
 Each row: id/source_id, platform, uid, name, auth (Mirai), agent_auth
 (Agent plugin), auth_hash, status/source_status, balance/balance_at,
 credential_at, signedToday/signed_date/signed_at/signed_known,
 needs_login, routing_state/routing_reason, quota.
 auth_hash is SHA256(canonical JSON of ORIGINAL stored auth, before aliases).
 credential_at uses credential-issued metadata, NEVER Account.updated_at.
 Signed evidence comes from schedules.last_result.items and last_run_at (UTC).
 Truncated/missing/old evidence is UNKNOWN, not an assertion of unsigned.

 upsert {accounts:[{platform,uid,name,auth,status,expected_auth_hash,...}]}
 -> {ok,results,items}; results == items, each result has
 {ok,platform,uid,status,source_id,id,created,auth_hash,credentialChanged}.
 source_id is parent-ledger metadata, not Mirai row identity.
 primary="agent2api" permits backup balance injection: finite balance, positive
 balance_at (milliseconds) strictly newer than both native balance timestamps.
 balance_remain uses native int(points/credits) semantics; balance_synced_at and
 credits_synced_at become the source observation time as naive UTC datetimes.
 No invented total/expiry breakdown; all other native quota fields are preserved.
 Each record has its own SQLite BEGIN IMMEDIATE transaction. Null CAS means
 expect absent; missing CAS accepts only identical merged auth on existing rows.
 Also accepts {account:record,expected_auth_hash:...} -> single result.
 Parent selects the newer credentials and supplies the complete merged auth.
 Known older credential timestamps are refused even with a matching CAS.
 Missing/empty incoming values preserve existing fields (no deletion API).
 New mirrors inherit the source switch; existing native switches are preserved.
 This module NEVER writes the Agent source or sets its enabled flag.
 Parent must preserve source enabled/user-disabled state in its own ledger.

 task {account_id:positive_int_or_decimal_string,action:checkin|balance|keepalive|activity|credential|
 ban_recheck}; alternatively {platform,uid,action}. Optional expected_auth_hash.
 -> EXACT {ok,status,message,balance,signed,credentialChanged}, no raw errors.
 WPS maintenance; CodeArts tasks belong to the primary 3065 plugin.
 Loomy credential maintenance requires backup_maintenance=true, uid and exact
 expected_auth_hash. It calls native stored-password renewal and keeps the
 backup account disabled through the commit. No signup or invitation hooks run.
 checkin uses checkin_account(...,claim_one_time=False).
 balance/keepalive use sync_quota(db,account), never the batch keepalive.
 activity preserves native enabled flag, daily deduplication and probability.
 WPS credential and bulk ban_recheck are unsupported. Native recheck cannot distinguish
 user-disabled accounts, so this adapter never attempts automatic recovery.
 Parent serializes tasks per account and persists task/checkin results; these
 single-account native calls do not update the batch schedule's last_result.

 take_ownership -> {ok,previous,disabled_ids,left_native,ownership_complete}.
 Only enabled on relevant Schedule rows is changed (ORM updated_at automatic).
 WPS activity and ban_recheck timers are disabled. Central single-account recheck requires provenance for disabled accounts; unknown runners are reported.
 Only WPS checkin/keepalive/refresh_balances are taken over by default. Activity
 has a callable replacement but its central scheduler is not yet integrated.
 Existing running native jobs are not cancelled. Parent must drain/coordinate
 them before dispatching central work; schedule changes do not stop in-flight
 work. No complete ownership claim while left_native contains enabled jobs.

Callable entry: handle(request, backend=None). NativeBackend lazily imports
the existing Account/Schedule ORM and SessionLocal; it does not call init_db.
Pure helpers are safe to import outside Mirai, without SQLAlchemy installed.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import importlib
import json
import logging
import math
import os
import re
import sys
from datetime import datetime, timedelta, timezone

PLATFORMS = ("loomy", "raccoon", "codearts", "wps-lingxi")
WPS = "wps-lingxi"
BACKUPS = frozenset(PLATFORMS[:3])
CN = timezone(timedelta(hours=8))
MISSING = object()
MAX_INPUT = 8 * 1024 * 1024
CODEARTS_ALIASES = {
    "access_key": ("access_key_id", "accessKey"),
    "secret_key": ("secret_access_key", "secretKey"),
    "security_token": ("securityToken",),
    "refresh_token": ("refreshToken",),
    "expires_at": ("expiresAt",),
    "user_name": ("userName",),
    "domain_id": ("domainId",),
    "client_id": ("clientId",),
    "dpop_private_key": ("dpopPrivateKey",),
    "dpop_public_key": ("dpopPublicKey",),
    "pkce_code_verifier": ("pkceCodeVerifier",),
}
CAPABILITIES = {
    "platforms": list(PLATFORMS),
    "tasks": {WPS: ["checkin", "balance", "keepalive", "activity", "recheck"],"loomy":["credential"]},
    "unsupported": {WPS: ["credential", "ban_recheck"],
                    "codearts": ["checkin", "balance", "credential"]},
    "signed_source": "schedule_snapshot",
    "private_inventory": True,
}


class BridgeError(Exception):
    """Only fixed, non-secret error codes cross the private runner boundary."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def auth_hash(auth):
    return hashlib.sha256(canonical(auth).encode("utf-8")).hexdigest()


def object_value(value):
    if isinstance(value, dict):
        return copy.deepcopy(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
    raise BridgeError("invalid_auth")


def platform_name(value):
    value = {"wps": WPS, "wps_lingxi": WPS}.get(value, value)
    if value not in PLATFORMS:
        raise BridgeError("unsupported_platform")
    return value


def uid_value(value):
    # UID is identity, never truncate, convert numeric IDs or derive from a token.
    if not isinstance(value, str) or not value or value != value.strip():
        raise BridgeError("invalid_uid")
    if len(value) > 120 or any(ord(c) < 32 for c in value):
        raise BridgeError("invalid_uid")
    return value


def timestamp_ms(value):
    if value is None or isinstance(value, bool) or value == "":
        return 0
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return max(0, int(value.timestamp() * 1000))
    try:
        n = float(value)
        if math.isfinite(n) and n > 0:
            return int(n * 1000 if n < 100_000_000_000 else n)
    except (TypeError, ValueError, OverflowError):
        pass
    if isinstance(value, str):
        try:
            return timestamp_ms(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except (ValueError, OverflowError):
            pass
    return 0


def credential_time(auth):
    # Expiration is NOT issuance. Row update/probe timestamps are NOT issuance.
    return max((timestamp_ms(auth.get(key)) for key in
                ("credential_at", "credential_updated_at", "updatedAt",
                 "issued_at", "issuedAt")), default=0)


def _first(data, keys):
    return next((data[k] for k in keys if data.get(k) not in (None, "")), None)


def normalize_auth(platform, auth, uid):
    """Preserve platform-local metadata; normalize only known credential aliases."""
    platform, uid = platform_name(platform), uid_value(uid)
    data = object_value(auth)
    for key in ("uid", "userid", "userId", "user_id"):
        if data.get(key) not in (None, "") and str(data[key]) != uid:
            raise BridgeError("uid_mismatch")
    data["uid"] = uid
    data.setdefault("realm", "cn")
    if platform == "loomy":
        token = _first(data, ("token", "session"))
        if token is not None:
            data["token"] = token
            if "session" in data:
                data["session"] = token
        if "expiresAt" in data and not data.get("expires_at"):
            data["expires_at"] = data["expiresAt"]
    elif platform == "raccoon":
        token = _first(data, ("token", "accessToken", "access_token", "session"))
        if token is not None:
            data["token"] = token
            # Native token_of prefers accessToken over token. Keep aliases coherent.
            for alias in ("accessToken", "access_token", "session"):
                if alias in data:
                    data[alias] = token
        refresh = _first(data, ("refresh_token", "refreshToken"))
        # Native importer invents refresh_token=token. Never export that as renewable.
        if refresh and refresh != token:
            data["refresh_token"] = refresh
            if "refreshToken" in data:
                data["refreshToken"] = refresh
        else:
            data.pop("refresh_token", None)
            data.pop("refreshToken", None)
        expires = _first(data, ("expires_at", "expiresAt"))
        if expires is not None:
            data["expires_at"] = timestamp_ms(expires)
    elif platform == "codearts":
        for key, aliases in CODEARTS_ALIASES.items():
            value = _first(data, (key,) + aliases)
            if value is not None:
                data[key] = value
                for alias in aliases:
                    if alias in data:
                        data[alias] = value
        if data.get("expires_at"):
            data["expires_at"] = timestamp_ms(data["expires_at"])
    else:
        if not data.get("cookie"):
            sid = _first(data, ("wps_sid", "sid"))
            if sid:
                data["cookie"] = "wps_sid=%s; uid=%s" % (sid, uid)
    return data


def agent_credentials(platform, auth, uid):
    """Normalized pluginSecret for outbound Agent mirroring, PRIVATE ONLY."""
    platform = platform_name(platform)
    data = normalize_auth(platform, auth, uid)
    # Older Raccoon imports store lightweight metadata here, newer mirrors retain
    # the original pluginSecret. Preserve it but overwrite credential aliases.
    out = copy.deepcopy(data.get("agent2api", {}))
    if not isinstance(out, dict):
        out = {}
    out.update({k: v for k, v in data.items() if k != "agent2api"})
    if platform == "loomy":
        out.update(session=data.get("token", ""), userid=uid)
    elif platform == "raccoon":
        out.update(accessToken=data.get("token", ""), userId=uid)
        if data.get("refresh_token"):
            out["refreshToken"] = data["refresh_token"]
        else:
            out.pop("refreshToken", None)
            out.pop("refresh_token", None)
        if data.get("expires_at"):
            out["expiresAt"] = data["expires_at"]
    elif platform == "codearts":
        out["access_key_id"] = data.get("access_key", "")
        out["secret_access_key"] = data.get("secret_key", "")
    return out


def _merge_nonempty(previous, incoming):
    merged = copy.deepcopy(previous)
    for key, value in incoming.items():
        if value is None or value == "":
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_nonempty(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def merged_auth(platform, uid, previous, incoming):
    incoming = normalize_auth(platform, incoming, uid)
    # Normalize aliases BEFORE merge so a new session replaces an old token.
    # Strip legacy synthesized refresh credentials before a token rotates.
    previous = normalize_auth(platform, previous, uid) if previous else {}
    result = _merge_nonempty(previous, incoming)
    return normalize_auth(platform, result, uid)


def target_status(platform, source_status, existing_status=None):
    if source_status not in ("active", "disabled"):
        raise BridgeError("invalid_status")
    # Maintenance never changes an existing account's operator-controlled switch.
    if existing_status in ("active", "disabled"):
        return existing_status
    # New mirrors inherit the requested switch. Maintenance never forces a
    # backup account off; existing switches remain owned by the native app.
    return source_status


def check_cas(previous, expected, changed):
    if previous is None:
        if expected is not MISSING and expected is not None:
            raise BridgeError("conflict")
        return
    if expected is MISSING:
        if changed:
            raise BridgeError("cas_required")
        return
    if not isinstance(expected, str) or not hmac.compare_digest(
            auth_hash(previous), expected):
        raise BridgeError("conflict")


def merge_plan(record, previous=None, existing_status=None):
    platform = platform_name(record.get("platform"))
    uid = uid_value(record.get("uid"))
    incoming = object_value(record.get("auth"))
    auth = merged_auth(platform, uid, previous or {}, incoming)
    required = {"loomy": ("token",), "raccoon": ("token",),
                "codearts": ("access_key", "secret_key"),
                WPS: ("cookie",)}[platform]
    if any(not isinstance(auth.get(k), str) or not auth[k].strip() for k in required):
        raise BridgeError("missing_credentials")
    old_time = credential_time(previous or {})
    new_time = timestamp_ms(record.get("credential_at")) or credential_time(incoming)
    if timestamp_ms(record.get("credential_at")):
        # Persist the parent's credential clock so the next merge can compare it.
        auth["credential_at"] = new_time
    changed = previous is None or canonical(auth) != canonical(previous)
    check_cas(previous, record.get("expected_auth_hash", MISSING), changed)
    if changed and old_time and new_time and new_time < old_time:
        raise BridgeError("stale_credentials")
    return {"platform": platform, "uid": uid, "auth": auth,
            "status": target_status(platform, record.get("status", "disabled"),
                                    existing_status),
            "credentialChanged": changed}


def number(value):
    if isinstance(value, bool):
        return None
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (ValueError, TypeError, OverflowError):
        return None



def inject_balance(account, record):
    """Mirror an observed Agent-primary balance only when it is strictly newer."""
    if account.platform not in BACKUPS or record.get("primary") != "agent2api":
        return False
    balance, at = number(record.get("balance")), number(record.get("balance_at"))
    if balance is None or at is None or at <= 0:
        return False
    previous = max(timestamp_ms(getattr(account, field, None))
                   for field in ("balance_synced_at", "credits_synced_at"))
    if at <= previous:
        return False
    try:
        observed = datetime.fromtimestamp(at / 1000, timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError, OSError):
        return False
    account.balance_remain = int(balance)
    account.balance_synced_at = observed
    account.credits_synced_at = observed
    return True


def signed_snapshot(schedules, now=None):
    """Only per-account positive evidence. Batch totals never imply per-user success."""
    now = now or datetime.now(timezone.utc)
    today = now.astimezone(CN).date().isoformat()
    found = {}
    for schedule in schedules:
        if schedule.platform != WPS or schedule.task != "wps_lingxi_checkin":
            continue
        at = timestamp_ms(schedule.last_run_at)
        if not at:
            continue
        day = datetime.fromtimestamp(at / 1000, CN).date().isoformat()
        try:
            data = object_value(schedule.last_result)
        except BridgeError:
            continue
        items = data.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or item.get("ok") is not True:
                continue
            if item.get("outcome") not in ("claimed", "done"):
                continue
            aid = item.get("account_id")
            if type(aid) is not int or aid <= 0:
                continue
            if at >= found.get(aid, {}).get("signed_at", 0):
                found[aid] = {"signedToday": True if day == today else None,
                              "signed_date": day, "signed_at": at,
                              "signed_known": day == today}
    return found


def quota_snapshot(value):
    try:
        data = object_value(value)
    except BridgeError:
        return {}
    allowed = ("total", "bonus_total", "bonus_used", "used_pct", "expiring_balance",
               "expiring_value", "batches", "remaining", "limit")
    return {key: number(data[key]) for key in allowed
            if key in data and number(data[key]) is not None}


def guarded_recheck(executor, db, account, token):
    from sqlalchemy import event, select
    from types import SimpleNamespace
    model=type(account)
    def check(session, flush_context, instances):
        columns=['id','status','updated_at','err_count','last_err_at','consecutive_fails','ban_kind','auth_json']
        live=session.connection().execute(select(*(getattr(model,k) for k in columns)).where(model.id==account.id)).mappings().first()
        if not live or not hmac.compare_digest(token,disabled_fingerprint(SimpleNamespace(**live))):
            raise BridgeError('conflict')
    event.listen(db,'before_flush',check)
    try:return executor('recheck',db,account)
    finally:event.remove(db,'before_flush',check)


def disabled_fingerprint(account):
    if account.status != 'disabled':return ''
    fields=[str(getattr(account,k,'')) for k in ('id','status','updated_at','err_count','last_err_at','consecutive_fails','ban_kind')]
    fields.append(auth_hash(object_value(account.auth_json)))
    return hashlib.sha256(json.dumps(fields).encode()).hexdigest()


def inventory_record(account, signed=None):
    raw = object_value(account.auth_json)
    platform = platform_name(account.platform)
    # Failed/disabled WPS imports can have no upstream UID. Show the existing
    # native row by local ID, but never invent a UID or make it syncable.
    uid = '' if platform == WPS and not account.uid else uid_value(account.uid)
    auth = normalize_auth(platform, raw, uid) if uid else raw
    quota = quota_snapshot(getattr(account, "credits_snapshot", ""))
    balance_at = max(timestamp_ms(getattr(account, field, None)) for field in
                     ("balance_synced_at", "credits_synced_at"))
    # last_sync_at can mean import/probe; it does not establish a balance snapshot.
    balance = number(account.balance_remain) if balance_at or quota else None
    status = account.status
    needs_login = bool(getattr(account, "session_dead_fails", 0))
    observation = object_value(getattr(account, 'credits_snapshot', '') or '{}').get('maintenance3067', {})
    if platform == WPS and observation.get('auth_hash') == auth_hash(raw):
        if observation.get('status') == 'needs_login': needs_login = True
        elif observation.get('status') == 'ok' and observation.get('observed_at', 0) > timestamp_ms(getattr(account, 'last_err_at', None)):
            needs_login = False
    now = datetime.now(timezone.utc)
    cooling = any(timestamp_ms(getattr(account, f, None)) > timestamp_ms(now)
                  for f in ("cool_until", "breaker_until", "degrade_until"))
    if status != "active":
        routing_state, reason = "disabled", "source_disabled"
    elif getattr(account, "ban_kind", ""):
        routing_state, reason = "blocked", "upstream_ban"
    elif cooling:
        routing_state, reason = "cooldown", "native_cooldown"
    else:
        routing_state, reason = "active", ""
    result = {
        "id": account.id, "source_id": account.id, "platform": platform,
        "uid": uid, "name": account.name, "auth": auth,
        "agent_auth": agent_credentials(platform, raw, uid) if uid else {},
        "auth_hash": auth_hash(raw), "status": status, "source_status": status,
        "balance": balance, "balance_at": balance_at,
        "credential_at": credential_time(raw), "needs_login": needs_login,
        "routing_state": routing_state, "routing_reason": reason, "quota": quota,
        "signedToday": None, "signed_date": None, "signed_at": 0,
        "signed_known": False,
        "disabled_fingerprint": disabled_fingerprint(account),
        "verification_status": observation.get('status') if observation.get('auth_hash') == auth_hash(raw) else None,
        "verification_at": observation.get('observed_at', 0) if observation.get('auth_hash') == auth_hash(raw) else 0,
        "verified_balance_at": (observation.get('balance_verified_at', 0) or (balance_at if observation.get('status') == 'ok' and balance_at == observation.get('observed_at') else 0)) if observation.get('auth_hash') == auth_hash(raw) else 0,
    }
    if platform == WPS and signed:
        result.update(signed)
    if platform == WPS and observation.get('auth_hash') == auth_hash(raw) and observation.get('signed_at'):
        result.update(signed_at=observation['signed_at'], signed_date=observation.get('signed_date'), signed_known=True)
    return result


def apply_wps_observation(row, request):
    """CAS guarded result write; never changes status, credentials or concurrency."""
    if row.platform != WPS: return {'ok': False, 'status': 'unsupported'}
    if row.status != 'active': return {'ok': False, 'status': 'disabled'}
    version = auth_hash(object_value(row.auth_json))
    if request.get('expected_auth_hash') != version: return {'ok': False, 'status': 'conflict'}
    at = request.get('observed_at')
    if type(at) is not int or at <= 0 or at > timestamp_ms(datetime.now(timezone.utc)) + 60000:
        raise BridgeError('invalid_observation')
    quota = object_value(getattr(row, 'credits_snapshot', '') or '{}')
    previous = quota.get('maintenance3067', {})
    if previous.get('result_id') == request.get('result_id'): return {'ok': True, 'status': 'unchanged'}
    if previous.get('observed_at', 0) >= at: return {'ok': False, 'status': 'stale'}
    status = request.get('status')
    if status not in ('ok', 'needs_login', 'error', 'cooling', 'unconfirmed'): raise BridgeError('invalid_observation')
    if status not in ('ok', 'needs_login'): return {'ok': True, 'status': 'no_auth_evidence'}
    observation = {'auth_hash': version, 'observed_at': at, 'status': status, 'result_id': request.get('result_id')}
    if previous.get('auth_hash') == version:
        for field in ('signed_at', 'signed_date', 'owned_cool_until', 'prior_cool_until', 'prior_cool_kind', 'balance_verified_at'):
            if field in previous: observation[field] = previous[field]
    current_cool = timestamp_ms(getattr(row, 'cool_until', None))
    if status == 'needs_login':
        until = at + 86400000
        if until > current_cool:
            if current_cool != previous.get('owned_cool_until'):
                observation['prior_cool_until'] = current_cool
                observation['prior_cool_kind'] = str(getattr(row, 'cool_kind', '') or '')
            row.cool_until = datetime.fromtimestamp(until / 1000, timezone.utc).replace(tzinfo=None)
            row.cool_kind = 'auth'
            observation['owned_cool_until'] = until
    elif current_cool and current_cool == previous.get('owned_cool_until') and timestamp_ms(getattr(row, 'last_err_at', None)) <= previous.get('observed_at', 0):
        # Clear only our exact cooldown, never a newer forwarding failure.
        prior = previous.get('prior_cool_until', 0)
        row.cool_until = datetime.fromtimestamp(prior / 1000, timezone.utc).replace(tzinfo=None) if prior > at else None
        row.cool_kind = previous.get('prior_cool_kind', '') if prior > at else ''
        observation.pop('owned_cool_until', None)
    if request.get('signed') and status == 'ok':
        observation.update(signed_at=request['signed_at'], signed_date=request['signed_date'])
    if 'balance' in request and status == 'ok':
        balance = request['balance']
        if isinstance(balance, bool) or not isinstance(balance, (int, float)) or not math.isfinite(balance) or balance < 0:
            raise BridgeError('invalid_balance')
        balance_at = max(timestamp_ms(getattr(row, f, None)) for f in ('balance_synced_at', 'credits_synced_at'))
        if at > balance_at:
            row.balance_remain = int(balance)
            stamp = datetime.fromtimestamp(at / 1000, timezone.utc).replace(tzinfo=None)
            row.balance_synced_at = row.credits_synced_at = stamp
            observation['balance_verified_at'] = at
            quota['total'] = balance
    quota['maintenance3067'] = observation
    row.credits_snapshot = canonical(quota)
    return {'ok': True, 'status': 'saved'}


def task_result(status, ok=False, balance=None, signed=None, changed=False):
    # Never interpolate native messages, SQL errors, names, cookie tails or URLs.
    messages = {
        "ok": "Task completed", "signed": "Daily checkin confirmed",
        "already_signed": "Daily checkin already completed",
        "unsupported": "Operation is not supported by this bridge",
        "not_due": "Credentials are not due for renewal",
        "disabled": "Account is disabled; no native task was called",
        "cooldown": "Account is cooling down or blocked",
        "already_active": "Account already had activity today",
        "probability_skip": "Native activity probability skipped this account",
        "activity_disabled": "Native daily activity is disabled",
        "needs_login": "Credentials require login",
        "conflict": "Credentials changed; refresh inventory",
        "not_found": "Account not found",
        "failed": "Native task failed",
    }
    return {"ok": ok, "status": status,
            "message": messages.get(status, "Request rejected"),
            "balance": number(balance), "signed": signed,
            "credentialChanged": bool(changed)}


def native_wps(action, db, account):
    """Signatures verified against the running v1.1.1 source, not guessed."""
    if action == 'credential' and account.platform == 'loomy':
        return native_loomy_credential(db, account)
    prefix = "admin.platform.wps_lingxi.services."
    if action in ("balance", "keepalive", "recheck"):
        return importlib.import_module(prefix + "accounts").sync_quota(db, account)
    if action == "checkin":
        return importlib.import_module(prefix + "checkin").checkin_account(
            db, account, claim_one_time=False)
    if action == "activity":
        activity = importlib.import_module(prefix + "activity")
        if not activity._enabled():
            return {"bridge_skip": "activity_disabled"}
        if activity._active_today(db, account):
            return {"bridge_skip": "already_active"}
        if not activity.humanize.human_probability(activity._probability()):
            return {"bridge_skip": "probability_skip"}
        return activity.activate_account(db, account)
    raise BridgeError("unsupported")


def native_loomy_credential(db, account):
    """Use Mirai's stored-password renewal without enabling a backup route."""
    from sqlalchemy import event, text
    service=importlib.import_module('admin.platform.loomy.services.accounts')
    before=object_value(account.auth_json);uid=str(account.uid);status=account.status
    if not service.has_password(before):return {'bridge_skip':'unsupported'}
    if not service.needs_renewal(before):return {'bridge_skip':'not_due'}
    expected=auth_hash(before)
    def preserve_backup(session, flush_context, instances):
        current=session.execute(text('select auth_json from accounts where id=:id'),{'id':account.id}).scalar_one()
        if auth_hash(object_value(current))!=expected:raise BridgeError('conflict')
        if str(object_value(account.auth_json).get('uid') or '')!=uid:raise BridgeError('identity_mismatch')
        account.status=status
    event.listen(db,'before_flush',preserve_backup)
    try:return service.renew_with_password(db,account)
    finally:event.remove(db,'before_flush',preserve_backup)


class NativeBackend:
    def __init__(self, session_factory=None, account_model=None, schedule_model=None,
                 executor=None, begin_write=None):
        if session_factory is None:
            # /tmp deployment still imports native /app code; never initializes DB.
            if "/app" not in sys.path:
                sys.path.insert(0, "/app")
            from admin.db import SessionLocal, engine
            from admin.models import Account, Schedule
            if engine.dialect.name != "sqlite" or os.path.realpath(
                    engine.url.database or "") != "/data/workbuddy.db":
                raise BridgeError("unexpected_database")
            session_factory, account_model, schedule_model = SessionLocal, Account, Schedule
        self.session_factory = session_factory
        self.Account, self.Schedule = account_model, schedule_model
        self.executor = executor or native_wps
        self.begin_write = begin_write or self._begin_write

    @staticmethod
    def _begin_write(db):
        from sqlalchemy import text
        # accounts has no unique (platform,uid) constraint. Serialize lookup+insert.
        db.execute(text("BEGIN IMMEDIATE"))

    def inventory(self, platform=None, uid=None, wps_only=False):
        with self.session_factory() as db:
            query = db.query(self.Account).filter(self.Account.platform.in_(PLATFORMS))
            if wps_only:query=query.filter(self.Account.platform==WPS)
            if platform is not None:
                query = query.filter(self.Account.platform == platform_name(platform), self.Account.uid == uid_value(uid))
            rows = query.order_by(self.Account.id).all()
            schedules = [] if platform is not None else db.query(self.Schedule).filter(self.Schedule.platform == WPS).all()
            evidence = signed_snapshot(schedules)
            items, rejected = [], []
            for row in rows:
                try:
                    items.append(inventory_record(row, evidence.get(row.id)))
                except BridgeError as exc:
                    # Never omit an unreadable account silently or expose its auth.
                    rejected.append({"id": row.id, "status": exc.code})
            return {"ok": not rejected, "items": items, "accounts": items,
                    "rejected": rejected, "capabilities": copy.deepcopy(CAPABILITIES)}

    def upsert(self, record):
        if not isinstance(record, dict):
            raise BridgeError("invalid_request")
        platform, uid = platform_name(record.get("platform")), uid_value(record.get("uid"))
        name = record.get("name", "")
        if not isinstance(name, str) or len(name) > 120:
            raise BridgeError("invalid_name")
        with self.session_factory() as db:
            try:
                self.begin_write(db)
                rows = db.query(self.Account).filter(
                    self.Account.platform == platform, self.Account.uid == uid).all()
                if len(rows) > 1:
                    raise BridgeError("ambiguous_identity")
                row = rows[0] if rows else None
                previous = object_value(row.auth_json) if row else None
                plan = merge_plan(record, previous, row.status if row else None)
                created = row is None
                if created:
                    row = self.Account(platform=platform, uid=uid, name=name or uid)
                    db.add(row)
                changed = (created or plan["credentialChanged"]
                           or row.status != plan["status"] or bool(name and row.name != name))
                row.auth_json = canonical(plan["auth"])
                row.status = plan["status"]
                if name:
                    row.name = name
                balance_changed = inject_balance(row, record)
                changed = changed or balance_changed
                # No error/cooldown resets; balance changes require newer evidence.
                if created:
                    row.domain = str(plan["auth"].get("realm") or "cn")[:120]
                db.flush()
                result = {"ok": True, "platform": platform, "uid": uid,
                          "created": created, "status": "created" if created else
                          "updated" if changed else "unchanged",
                          "id": row.id, "source_id": row.id,
                          "auth_hash": auth_hash(plan["auth"]),
                          "credentialChanged": plan["credentialChanged"],
                          "balanceChanged": balance_changed}
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    def task(self, request):
        action = request.get("action")
        if action == 'maintenance_result':
            aid = str(request.get('account_id', ''))
            if not re.fullmatch(r'[0-9]{1,19}', aid): raise BridgeError('invalid_account_id')
            with self.session_factory() as db:
                self.begin_write(db)
                rows = db.query(self.Account).filter(self.Account.id == int(aid)).all()
                if not rows: return {'ok': False, 'status': 'not_found'}
                reply = apply_wps_observation(rows[0], request)
                db.commit()
                return reply
        if action not in ("balance", "checkin", "keepalive", "activity", "credential", "recheck"):
            return task_result("unsupported")
        with self.session_factory() as db:
            if "account_id" in request:
                aid = request["account_id"]
                if isinstance(aid, str) and re.fullmatch(r"[0-9]{1,19}", aid):
                    aid = int(aid)
                if type(aid) is not int or aid <= 0 or aid > 9223372036854775807:
                    raise BridgeError("invalid_account_id")
                rows = db.query(self.Account).filter(self.Account.id == aid).all()
            else:
                platform = platform_name(request.get("platform"))
                uid = uid_value(request.get("uid"))
                rows = db.query(self.Account).filter(
                    self.Account.platform == platform, self.Account.uid == uid).all()
            if not rows:
                return task_result("not_found")
            if len(rows) != 1:
                raise BridgeError("ambiguous_identity")
            row = rows[0]
            loomy_renewal=row.platform=='loomy' and action=='credential' and request.get('backup_maintenance') is True
            if row.platform==WPS and action=='credential':return task_result('unsupported')
            if row.platform != WPS and not loomy_renewal:
                return task_result("unsupported")
            if loomy_renewal and (not request.get('expected_auth_hash') or request.get('uid')!=row.uid):
                return task_result('conflict')
            # Optional selectors are assertions, not alternatives to account_id.
            if ("platform" in request and platform_name(request["platform"]) != row.platform
                    or "uid" in request and request["uid"] != row.uid):
                raise BridgeError("identity_mismatch")
            auto_disabled = (action=='recheck' and row.status=='disabled'
                and bool(request.get('auto_disable_token'))
                and hmac.compare_digest(str(request['auto_disable_token']),disabled_fingerprint(row)))
            if row.status != "active" and not loomy_renewal and not auto_disabled:
                return task_result("disabled")
            now = timestamp_ms(datetime.now(timezone.utc))
            if getattr(row, "ban_kind", "") or (not loomy_renewal and any(
                    timestamp_ms(getattr(row, f, None)) > now
                    for f in ("cool_until", "breaker_until", "degrade_until"))):
                return task_result("cooldown")
            before = auth_hash(object_value(row.auth_json))
            expected = request.get("expected_auth_hash", before)
            if not isinstance(expected, str) or not hmac.compare_digest(expected, before):
                return task_result("conflict")
            was_active=row.status=='active'
            try:
                if auto_disabled:
                    # Native sync_quota enables disabled rows. Reject a stale
                    # recovery if an operator changed the row during the call.
                    result = guarded_recheck(self.executor, db, row, request['auto_disable_token'])
                else:result = self.executor(action, db, row)
                # Native functions commit internally. Refresh actual persisted fields.
                db.refresh(row)
                if auto_disabled and result.get('ok') and row.status!='active':return task_result('conflict')
                changed = auth_hash(object_value(row.auth_json)) != before
                balance_at = max(timestamp_ms(getattr(row, f, None)) for f in
                                 ("credits_synced_at", "balance_synced_at"))
                balance = row.balance_remain if balance_at else None
                if result.get("bridge_skip"):
                    return task_result(result["bridge_skip"], balance=balance, changed=changed)
                ok = result.get("ok") is True
                if action=='credential' and not changed:return task_result('failed')
                outcome = result.get("outcome")
                if ok and action == "checkin" and outcome in ("claimed", "done"):
                    return task_result("signed" if outcome == "claimed" else "already_signed",
                                       True, balance, True, changed)
                error = result.get("error") if isinstance(result.get("error"), dict) else {}
                status = "needs_login" if (outcome == "expired" or
                         error.get("kind") == "auth" or result.get("kind") == "auth") else (
                         "ok" if ok and action != "checkin" else "failed")
                response=task_result(status, status == "ok", balance, changed=changed)
                if status=='ok' and action in ('balance','keepalive','recheck') and balance_at:
                    response['balanceAt']=balance_at
                if status=='needs_login' and (was_active or auto_disabled) and row.status=='disabled':
                    response['auto_disable_token']=disabled_fingerprint(row)
                return response
            except Exception:
                db.rollback()
                # A native call can have committed before raising. Never retry here.
                return task_result("failed")

    def take_ownership(self):
        with self.session_factory() as db:
            try:
                self.begin_write(db)
                rows = db.query(self.Schedule).filter(
                    self.Schedule.platform.in_(PLATFORMS)).order_by(self.Schedule.id).all()
                previous, disabled, left = [], [], []
                wps_owned = {"wps_lingxi_checkin", "wps_lingxi_keepalive",
                             "refresh_balances", "wps_lingxi_activity", "wps_lingxi_ban_recheck"}
                for row in rows:
                    safe = {"id": row.id, "platform": row.platform, "task": row.task,
                            "enabled": row.enabled,
                            "next_run_at": timestamp_ms(row.next_run_at)}
                    if row.platform == WPS:
                        left.append(safe)
                        continue
                    previous.append(safe)
                    if row.enabled:
                        row.enabled = 0
                        disabled.append(row.id)
                db.commit()
                return {"ok": True, "previous": previous, "disabled_ids": disabled,
                        "left_native": left,
                        "ownership_complete": not any(r["enabled"] for r in left)}
            except Exception:
                db.rollback()
                raise


def _failure(exc):
    code = exc.code if isinstance(exc, BridgeError) else "internal_error"
    return {"ok": False, "status": code, "message": "Bridge request rejected"}


def _upsert_failure(exc, record):
    failure = dict(_failure(exc), platform=None, uid=None, id=None,
                   source_id=None, created=False)
    if isinstance(record, dict):
        try:
            failure.update(platform=platform_name(record.get("platform")),
                           uid=uid_value(record.get("uid")))
        except (BridgeError, TypeError):
            pass
    return failure


def runtime_inventory():
    """Observe the running server over its admin API, never a fresh local POOL.

    The local operator session is private, reused, and does not revoke browser
    sessions. The returned structure contains no credentials or request text.
    """
    import pathlib
    import urllib.request
    import urllib.error
    if '/app' not in sys.path:
        sys.path.insert(0, '/app')
    from admin.security import create_admin_token
    from admin.db import SessionLocal, engine
    if engine.dialect.name != 'sqlite' or os.path.realpath(engine.url.database or '') != '/data/workbuddy.db':
        raise BridgeError('unexpected_database')
    from admin.models import Account
    from admin.pool import is_cold, COLD_WARMUP_INFLIGHT
    from admin.platform.sentinel_router import _load_pause
    token_path = pathlib.Path('/tmp/maintenance-runtime-token')
    for attempt in range(2):
        if not token_path.exists():
            token_path.touch(mode=0o600)
            token_path.write_text(create_admin_token())
        req = urllib.request.Request('http://127.0.0.1:8790/api/sentinel/pool-snapshot',
                                     headers={'X-Admin-Token': token_path.read_text()})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=8) as response:
                pressure = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 401 or attempt:
                raise BridgeError('runtime_unavailable') from None
            token_path.unlink(missing_ok=True)
    pool = pressure['pool']
    inflight = {str(uid): int(n) for uid, n in pool['inflight'].items() if int(n) > 0}
    complete = (pressure.get('complete') is True and len(inflight) == int(pool['accounts_with_inflight']) and
                sum(inflight.values()) == int(pool['inflight_total']))
    now = datetime.now(timezone.utc)
    now_ms = timestamp_ms(now)
    with SessionLocal() as db:
        # Only the columns needed for routing; auth_json is not read here.
        from sqlalchemy.orm import load_only
        rows = db.query(Account).options(load_only(
            Account.id, Account.uid, Account.status, Account.max_in_flight,
            Account.cool_until, Account.breaker_until, Account.degrade_until,
            Account.last_used_at, Account.created_at, Account.ban_kind, Account.cool_kind)).filter(
                Account.platform == WPS).all()
        pause = _load_pause(db)
        paused = pause.get(WPS) or pause.get('all') or {}
        paused = bool(paused and (not paused.get('until') or float(paused['until']) * 1000 > now_ms))
        from sqlalchemy import inspect, text
        gates = {}
        if inspect(db.bind).has_table('wps_recovery_gates'):
            for g in db.execute(text("SELECT identity,model,kind,last_probe_at,next_probe_at,last_probe_result FROM wps_recovery_gates WHERE state!='released'")).mappings():
                gates.setdefault(g['identity'], []).append({'model':g['model'],'kind':g['kind'],
                    'lastProbeAt':timestamp_ms(g['last_probe_at']), 'nextProbeAt':timestamp_ms(g['next_probe_at']),
                    'result':g['last_probe_result'] or ''})
        accounts = []
        for row in rows:
            state, reason = 'usable', ''
            if row.status != 'active':
                state, reason = 'disabled', '3066账号已停用'
            elif paused:
                state, reason = 'blocked', '3066平台已暂停'
            elif not row.uid or row.ban_kind:
                state, reason = 'blocked', '账号身份缺失或上游限制'
            elif any(timestamp_ms(getattr(row, f)) > now_ms for f in ('cool_until', 'breaker_until', 'degrade_until')):
                state, reason = 'cooldown', '3066原生冷却中'
            recovery = gates.get(str(row.uid or '').strip() or 'account:'+str(row.id), [])
            reason_key = ''
            if recovery:
                kinds = {g['kind'] for g in recovery}
                reason_key = 'identity_required' if 'identity' in kinds else 'model_permission' if 'permission' in kinds else 'rate_limited'
                state, reason = 'recovery', {'identity_required':'上游明确要求实名，等待处理', 'model_permission':'3066已隔离，等待对应模型完成有效回答后恢复', 'rate_limited':'3066限流隔离，等待复测通过'}[reason_key]
            elif state == 'cooldown' and row.cool_kind == 'auth':
                state, reason = 'auth_failed', '3066记录登录失效，等待凭证恢复'
            elif state == 'cooldown':
                reason_key = 'rate_limited' if row.cool_kind in ('rate','soft_rate') else 'network_cooling' if row.cool_kind in ('network','stream_idle') else 'response_cooling' if row.cool_kind in ('upstream','empty','fatal') else 'native_cooling'
            limit = max(0, int(row.max_in_flight if row.max_in_flight is not None else pool['max_in_flight_per_account']))
            if limit and is_cold(row):
                limit = min(limit, COLD_WARMUP_INFLIGHT)
            accounts.append({'id': row.id, 'uid': row.uid or '', 'state': state, 'reason': reason, 'limit': limit, 'reasonKey':reason_key, 'recovery':recovery})
    return {'ok': True, 'accounts': accounts, 'inflight': inflight, 'complete': complete}


def handle(request, backend=None):
    """Return only allowlisted structures; exceptions never carry raw credentials."""
    command = request.get("command") if isinstance(request, dict) else None
    try:
        if command not in ("inventory", "upsert", "task", "take_ownership"):
            raise BridgeError("invalid_command")
        if command == "inventory" and request.get('view') == 'runtime':
            return runtime_inventory()
        backend = backend or NativeBackend()
        if command == "inventory":
            if request.get('view')=='wps':return backend.inventory(wps_only=True)
            if request.get('platform') is not None:
                return backend.inventory(request['platform'],request.get('uid'))
            return backend.inventory()
        if command == "take_ownership":
            return backend.take_ownership()
        if command == "task":
            return backend.task(request)
        if "accounts" in request:
            records = request["accounts"]
            if not isinstance(records, list) or len(records) > 500:
                raise BridgeError("invalid_accounts")
            items = []
            for record in records:
                try:
                    items.append(backend.upsert(record))
                except Exception as exc:
                    items.append(_upsert_failure(exc, record))
            return {"ok": all(item["ok"] for item in items),
                    "results": items, "items": items}
        record = copy.deepcopy(request.get("account"))
        if not isinstance(record, dict):
            raise BridgeError("invalid_account")
        if "expected_auth_hash" in request:
            record["expected_auth_hash"] = request["expected_auth_hash"]
        try:
            return backend.upsert(record)
        except Exception as exc:
            return _upsert_failure(exc, record)
    except Exception as exc:
        if command == "task":
            status = exc.code if isinstance(exc, BridgeError) else "failed"
            return task_result(status)
        return _failure(exc)


@contextlib.contextmanager
def quiet_native():
    """Mute native prints/logs, including FD writes, instead of leaking to stderr."""
    prior = logging.root.manager.disable
    with open(os.devnull, "w", encoding="utf-8") as sink:
        copies = []
        try:
            logging.disable(sys.maxsize)
            for stream in (sys.stdout, sys.stderr):
                try:
                    stream.flush()
                    fd = stream.fileno()
                    saved = os.dup(fd)
                    copies.append((fd, saved))
                    os.dup2(sink.fileno(), fd)
                except (AttributeError, OSError, ValueError):
                    pass
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                yield
        finally:
            for fd, saved in reversed(copies):
                os.dup2(saved, fd)
                os.close(saved)
            logging.disable(prior)


def main():
    request = None
    protocol_error = False
    try:
        if sys.stdin.isatty() or sys.stdout.isatty():
            raise BridgeError("private_pipe_required")
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise BridgeError("request_too_large")
        request = json.loads(raw.decode("utf-8-sig"))
        with quiet_native():
            result = handle(request)
    except Exception as exc:
        protocol_error = True
        result = _failure(exc)
    sys.stdout.write(canonical(result) + "\n")
    sys.stdout.flush()
    # Valid protocol replies include per-account failures; the host must receive
    # them rather than replacing useful structured results with helper_failed.
    return 1 if protocol_error else 0


if __name__ == "__main__":
    raise SystemExit(main())

