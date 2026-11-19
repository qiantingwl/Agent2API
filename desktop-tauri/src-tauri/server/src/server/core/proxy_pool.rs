//! 命名代理池：手动地址与 Clash Verge 端点按 `{source:'pool', proxyId}` 引用。
//! 条目与最近一次测试结果存于 kv 的 `proxyPool` 保留键。
//! 订阅镜像复用 v3.3.0-beta.4 的内核节点与稳定引用实现。

use std::sync::{Mutex, MutexGuard, OnceLock};

use serde_json::{json, Value};

use crate::server::core::proxies::{resolve_account_proxy, ProxyResolution};
use crate::server::db::Db;
use crate::server::logging;

pub mod usage;
mod import;
#[cfg(test)]
mod subscription_tests;

pub const KV_KEY: &str = "proxyPool";
pub const RETIRED_HINT: &str = "不支持的代理来源，请在网络代理页重新选择手动代理、Clash Verge 或订阅节点";

const CLASH_READONLY_HINT: &str = "该代理来自 Clash Verge 同步，请到 Clash Verge 中修改名称或端口；本页可启停和测试";

const MAX_NAME_LENGTH: usize = 60;
const MAX_LABEL_LENGTH: usize = 100;

static DB: OnceLock<Option<Db>> = OnceLock::new();
static MUTATIONS: Mutex<()> = Mutex::new(());

fn mutation_lock() -> MutexGuard<'static, ()> {
    MUTATIONS.lock().unwrap_or_else(|error| error.into_inner())
}

pub fn install(db: Option<Db>) {
    let _ = DB.set(db);
}

fn database() -> Result<&'static Db, String> {
    DB.get()
        .and_then(Option::as_ref)
        .ok_or_else(|| "代理池数据库不可用".to_string())
}

fn read_items() -> Vec<Value> {
    let Some(db) = DB.get().and_then(Option::as_ref) else {
        return Vec::new();
    };
    db.with(|conn| {
        conn.query_row("SELECT value FROM kv WHERE key = ?1", [KV_KEY], |row| {
            row.get::<_, String>(0)
        })
        .ok()
    })
    .flatten()
    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    .and_then(|value| value.get("items").and_then(Value::as_array).cloned())
    .unwrap_or_default()
}

fn is_manual(item: &Value) -> bool {
    matches!(item.get("source").and_then(Value::as_str), None | Some("" | "manual" | "custom"))
}

fn is_clash(item: &Value) -> bool {
    item.get("source").and_then(Value::as_str) == Some("clash")
}

fn is_supported(item: &Value) -> bool {
    is_manual(item) || is_clash(item) || is_subscription_item(item)
}

pub(crate) fn raw_items() -> Vec<Value> {
    read_items().into_iter().filter(is_supported).collect()
}

fn write_items(items: &[Value]) -> Result<(), String> {
    let _usage_guard = crate::server::core::usage_query::config::lock();
    let db = database()?;
    let text = serde_json::to_string(&json!({ "items": items }))
        .map_err(|error| format!("编码代理池失败: {error}"))?;
    let written = db
        .with(|conn| {
            conn.execute(
                "INSERT INTO kv (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![KV_KEY, text],
            )
            .map(|_| ())
            .map_err(|error| format!("保存代理池失败: {error}"))
        })
        .ok_or_else(|| "代理池数据库不可用".to_string())?;
    written?;
    crate::server::core::panel_events::notify(crate::server::core::panel_events::Change::Proxies);
    crate::server::core::cloud_sync::auto_sync::notify_change();
    Ok(())
}

fn clean_string(value: Option<&Value>, max: usize) -> String {
    let Some(Value::String(text)) = value else {
        return String::new();
    };
    text.trim().chars().take(max).collect()
}

fn valid_port(value: Option<&Value>) -> Option<u16> {
    let number = match value {
        Some(Value::Number(number)) => number.as_f64()?,
        Some(Value::String(text)) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if !number.is_finite() || number.fract() != 0.0 || !(1.0..=65535.0).contains(&number) {
        return None;
    }
    Some(number as u16)
}

fn text_of(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn normalize_item(input: &Value, existing: Option<&Value>) -> Result<Value, String> {
    let Some(object) = input.as_object() else {
        return Err("代理条目必须是对象".to_string());
    };
    if is_clash(input) {
        return Err("Clash Verge 出口由「同步 Clash Verge」自动导入，不能手工新建".to_string());
    }
    if !is_manual(input) {
        return Err(RETIRED_HINT.to_string());
    }
    let name = clean_string(object.get("name"), MAX_NAME_LENGTH);
    if name.is_empty() {
        return Err("请填写代理名称".to_string());
    }
    let protocol = clean_string(object.get("protocol"), 10).to_lowercase();
    let protocol = if protocol.is_empty() { "http".to_string() } else { protocol };
    if protocol != "http" && protocol != "socks5" {
        return Err("代理协议只支持 http 或 socks5".to_string());
    }
    let host = crate::server::core::proxies::normalize_host(object.get("host").and_then(Value::as_str).unwrap_or(""))?;
    let non_direct = crate::server::core::proxies::normalize_non_direct(
        object.get("nonDirect").or_else(|| existing.and_then(|item| item.get("nonDirect"))),
    )?;
    let Some(port) = valid_port(object.get("port")) else {
        return Err("代理端口必须是 1-65535 的整数".to_string());
    };
    let now = logging::now_ms();
    let id = existing.map(|item| text_of(item, "id")).unwrap_or_default();
    let id = if id.is_empty() { new_id() } else { id };
    let created_at = existing
        .and_then(|item| item.get("createdAt"))
        .and_then(Value::as_i64)
        .unwrap_or(now);
    // 测试结果保留为历史事实，时刻由界面显示，不参与实际选路。
    let last_test = existing
        .and_then(|item| item.get("lastTest"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(json!({
        "id": id,
        "name": name,
        "source": "manual",
        "enabled": !matches!(object.get("enabled"), Some(Value::Bool(false))),
        "protocol": protocol,
        "host": host,
        "port": port,
        "username": crate::server::core::proxies::normalize_credential(object.get("username"))?,
        "password": crate::server::core::proxies::normalize_credential(object.get("password"))?,
        "nonDirect": non_direct,
        "createdAt": created_at,
        "updatedAt": now,
        "lastTest": last_test,
    }))
}

fn new_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(logging::now_ms() as u64);
    hasher.write_u64(std::process::id() as u64);
    let suffix = (hasher.finish() & 0xffff_ffff) as u32;
    format!("px_{}_{suffix:08x}", logging::now_ms())
}

pub fn is_enabled(item: &Value) -> bool {
    is_supported(item)
        && !matches!(item.get("enabled"), Some(Value::Bool(false)))
        && !matches!(item.get("localDisabled"), Some(Value::Bool(true)))
}

pub fn resolve_item(item: &Value) -> Option<ProxyResolution> {
    if is_subscription_item(item) {
        let Some(port) = valid_port(item.get("port")) else {
            // 无引用或内核重建中的节点没有端口，与所属订阅已移除分开报错
            //
            // 「没有端口」是未引用节点的**正常状态**而不是待补建的缺口：
            // 测试走统一测试口（见模块头），不再需要端口；地址只在「真在用」
            // 时存在。
            let node_alive = crate::server::core::subscriptions::ids()
                .contains(&text_of(item, "providerId"));
            return Some(ProxyResolution::Failed(if node_alive {
                "该节点的监听端口尚未就绪（在账号或更新设置中选中并保存后，内核会自动分配端口；已保存的请稍等或检查内核状态）".to_string()
            } else {
                "订阅节点已不存在（订阅更新后节点被移除，等下一次同步或重新订阅）".to_string()
            }));
        };
        return Some(ProxyResolution::Resolved(crate::server::core::proxies::ResolvedProxy {
            source: "pool".to_string(),
            protocol: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: Some(port),
            username: String::new(),
            password: String::new(),
            label: String::new(),
            non_direct: false,
        }));
    }

    if is_clash(item) {
        return resolve_account_proxy(Some(&json!({
            "source": "clash",
            "listenerUid": text_of(item, "listenerUid"),
        })));
    }
    if !is_manual(item) {
        return Some(ProxyResolution::Failed(RETIRED_HINT.to_string()));
    }
    resolve_account_proxy(Some(&json!({
        "source": "custom",
        "protocol": text_of(item, "protocol"),
        "host": text_of(item, "host"),
        "port": item.get("port").cloned().unwrap_or(Value::Null),
        "username": text_of(item, "username"),
        "password": text_of(item, "password"),
        "nonDirect": item.get("nonDirect").cloned().unwrap_or(Value::Bool(false)),
    })))
}

pub fn resolve_reference(proxy_id: &str) -> Result<crate::server::core::proxies::ResolvedProxy, String> {
    let item = find_raw(proxy_id)?;
    if !is_supported(&item) {
        return Err(RETIRED_HINT.to_string());
    }
    if !is_enabled(&item) {
        return Err(format!(
            "代理「{}」已禁用（在「网络代理」页启用它）",
            display_name(&item, proxy_id)
        ));
    }
    resolve_entry(&item, proxy_id)
}

pub fn resolve_for_test(proxy_id: &str) -> Result<crate::server::core::proxies::ResolvedProxy, String> {
    resolve_entry(&find_raw(proxy_id)?, proxy_id)
}

fn display_name(item: &Value, fallback: &str) -> String {
    let name = text_of(item, "name");
    if name.is_empty() { fallback.to_string() } else { name }
}

fn resolve_entry(
    item: &Value,
    proxy_id: &str,
) -> Result<crate::server::core::proxies::ResolvedProxy, String> {
    let name = display_name(item, proxy_id);
    match resolve_item(item) {
        Some(ProxyResolution::Resolved(mut proxy)) => {
            proxy.label = name;
            Ok(proxy)
        }
        Some(ProxyResolution::Failed(reason)) => Err(format!("代理「{name}」不可用: {reason}")),
        None => Err(format!("代理「{name}」配置不完整")),
    }
}

fn describe_item(item: &Value) -> Value {
    let (resolved, resolve_error) = match resolve_item(item) {
        Some(ProxyResolution::Resolved(proxy)) => (
            json!({ "protocol": proxy.protocol, "host": proxy.host, "port": proxy.port_json(), "label": proxy.label }),
            Value::Null,
        ),
        Some(ProxyResolution::Failed(reason)) => (Value::Null, Value::String(reason)),
        None => (Value::Null, Value::String("配置不完整".to_string())),
    };
    json!({
        "id": text_of(item, "id"),
        "name": text_of(item, "name"),
        "source": if is_subscription_item(item) { "subscription" } else if is_clash(item) { "clash" } else { "manual" },
        "providerId": item.get("providerId"), "providerName": item.get("providerName"), "node": item.get("node"),
        "enabled": is_enabled(item),
        "sourceEnabled": !matches!(item.get("enabled"), Some(Value::Bool(false))),
        "localDisabled": matches!(item.get("localDisabled"), Some(Value::Bool(true))),
        "listenerUid": text_of(item, "listenerUid"),
        "protocol": text_of(item, "protocol"),
        "host": text_of(item, "host"),
        "port": item.get("port").cloned().unwrap_or(Value::Null),
        "username": text_of(item, "username"),
        "password": text_of(item, "password"),
        "nonDirect": item.get("nonDirect").and_then(Value::as_bool).unwrap_or(false),
        "createdAt": item.get("createdAt").cloned().unwrap_or(Value::from(0)),
        "updatedAt": item.get("updatedAt").cloned().unwrap_or(Value::from(0)),
        "lastTest": item.get("lastTest").cloned().unwrap_or(Value::Null),
        "resolved": resolved,
        "resolveError": resolve_error,
    })
}

pub fn list() -> Vec<Value> {
    raw_items().iter().map(describe_item).collect()
}

fn find_raw(id: &str) -> Result<Value, String> {
    // Account list rendering resolves one proxy per account. Cache an indexed
    // pool for the current SQLite revision instead of parsing the full pool
    // thousands of times. Both local and external commits invalidate it.
    static LOOKUP: OnceLock<Mutex<PoolLookup>> = OnceLock::new();
    database().ok().and_then(|db| db.with(|conn| {
        LOOKUP.get_or_init(|| Mutex::new(PoolLookup::default()))
            .lock().unwrap_or_else(|error| error.into_inner()).find(conn, id)
    }).flatten())
        .ok_or_else(|| format!("代理「{id}」不存在或已被删除"))
}

#[derive(Default)]
struct PoolLookup {
    revision: Option<(i64, i64)>,
    items: std::collections::HashMap<String, Value>,
}

impl PoolLookup {
    fn find(&mut self, conn: &rusqlite::Connection, id: &str) -> Option<Value> {
        let version: i64 = conn.pragma_query_value(None, "data_version", |row| row.get(0)).ok()?;
        let changes: i64 = conn.query_row("SELECT total_changes()", [], |row| row.get(0)).ok()?;
        if self.revision != Some((version, changes)) {
            let text: String = conn.query_row("SELECT value FROM kv WHERE key = ?1", [KV_KEY], |row| row.get(0)).ok()?;
            let value: Value = serde_json::from_str(&text).ok()?;
            self.items = value.get("items")?.as_array()?.iter().filter_map(|item|
                Some((item.get("id")?.as_str()?.to_string(), item.clone()))).collect();
            self.revision = Some((version, changes));
        }
        self.items.get(id).cloned()
    }
}

#[cfg(test)]
mod pool_lookup_tests {
    use super::*;
    #[test]
    fn cached_lookup_observes_local_and_external_changes() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let conn = rusqlite::Connection::open(file.path()).unwrap();
        conn.execute_batch("CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT); INSERT INTO kv VALUES('proxyPool','{\"items\":[{\"id\":\"node\",\"enabled\":true}]}');").unwrap();
        let mut lookup = PoolLookup::default();
        assert_eq!(lookup.find(&conn, "node").unwrap()["enabled"], true);
        conn.execute("UPDATE kv SET value=?", [r#"{"items":[{"id":"node","enabled":false}]}"#]).unwrap();
        assert_eq!(lookup.find(&conn, "node").unwrap()["enabled"], false);
        let external = rusqlite::Connection::open(file.path()).unwrap();
        external.execute("UPDATE kv SET value=?", [r#"{"items":[]}"#]).unwrap();
        assert!(lookup.find(&conn, "node").is_none());
    }
}

pub fn create_batch(input: &Value) -> Result<Value, String> {
    import::create(input)
}

pub fn create(input: &Value) -> Result<(), String> {
    let _guard = mutation_lock();
    let item = normalize_item(input, None)?;
    let mut items = read_items();
    items.insert(0, item.clone());
    write_items(&items)?;
    logging::log("[Proxies]", &format!("✅ 新增代理「{}」", text_of(&item, "name")));
    Ok(())
}

pub fn update(input: &Value) -> Result<(), String> {
    let _guard = mutation_lock();
    let id = clean_string(input.get("id"), MAX_LABEL_LENGTH);
    if id.is_empty() {
        return Err("缺少代理 id".to_string());
    }
    let mut items = read_items();
    let index = writable_index(&items, &id)?;
    let next = normalize_item(input, Some(&items[index]))?;
    items[index] = next.clone();
    write_items(&items)?;
    logging::log("[Proxies]", &format!("✅ 更新代理「{}」", text_of(&next, "name")));
    Ok(())
}

fn writable_index(items: &[Value], id: &str) -> Result<usize, String> {
    let index = items.iter()
        .position(|item| item.get("id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("代理「{id}」不存在"))?;
    if !is_supported(&items[index]) {
        return Err(RETIRED_HINT.to_string());
    }
    if is_subscription_item(&items[index]) { return Err("订阅节点由订阅管理维护，不能手工修改".into()); }
    if is_clash(&items[index]) {
        return Err(CLASH_READONLY_HINT.to_string());
    }
    Ok(index)
}

fn supported_index(items: &[Value], id: &str) -> Result<usize, String> {
    let index = items.iter()
        .position(|item| item.get("id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("代理「{id}」不存在"))?;
    if !is_supported(&items[index]) {
        return Err(RETIRED_HINT.to_string());
    }
    Ok(index)
}

pub struct EnabledChange {
    pub source: String,
    pub name: String,
    pub enabled: bool,
}

pub fn set_enabled(id: &str, enabled: bool) -> Result<EnabledChange, String> {
    let _guard = mutation_lock();
    let mut items = read_items();
    let index = supported_index(&items, id)?;
    let name = display_name(&items[index], id);
    let source = text_of(&items[index], "source");
    let clash = is_clash(&items[index]) || is_subscription_item(&items[index]);
    if clash && enabled && matches!(items[index].get("enabled"), Some(Value::Bool(false))) {
        return Err("这条在 Clash Verge 里是停用的，请到 Clash Verge 里打开它".to_string());
    }
    let Some(object) = items[index].as_object_mut() else {
        return Err("代理条目形状异常".to_string());
    };
    if clash {
        if enabled {
            object.remove("localDisabled");
        } else {
            object.insert("localDisabled".to_string(), Value::Bool(true));
        }
    } else {
        object.insert("enabled".to_string(), Value::Bool(enabled));
    }
    object.insert("updatedAt".to_string(), Value::from(logging::now_ms()));
    write_items(&items)?;
    logging::log("[Proxies]", &format!("{}代理「{name}」", if enabled { "✅ 启用" } else { "⏸️ 禁用" }));
    Ok(EnabledChange { name, enabled, source })
}

pub fn remove(id: &str) -> Result<String, String> {
    let _guard = mutation_lock();
    let mut items = read_items();
    let index = writable_index(&items, id)?;
    let removed = items.remove(index);
    write_items(&items)?;
    let name = text_of(&removed, "name");
    logging::log("[Proxies]", &format!("🗑️ 删除代理「{name}」"));
    Ok(name)
}

pub struct ClashSyncReport {
    pub changes: usize,
    pub error: Option<String>,
}

pub fn sync_clash(force: bool) -> ClashSyncReport {
    let snapshot = crate::server::core::clash::clash_snapshot_with(force);
    if !snapshot.available {
        return ClashSyncReport {
            changes: 0,
            error: Some(snapshot.error.unwrap_or_else(||
                crate::server::core::clash::CLASH_UNAVAILABLE.to_string())),
        };
    }
    let mut targets = Vec::new();
    if snapshot.mixed_port.is_some() {
        targets.push((
            crate::server::core::clash::CLASH_MIXED_UID.to_string(),
            "Clash 混合端口（按规则分流）".to_string(),
            true,
        ));
    }
    for listener in snapshot.listeners {
        targets.push((listener.uid, listener.name, listener.enabled));
    }
    let _guard = mutation_lock();
    let mut items = read_items();
    let mut changes = 0;
    let now = logging::now_ms();
    for (uid, name, enabled) in &targets {
        if let Some(index) = items.iter().position(|item| is_clash(item)
            && item.get("listenerUid").and_then(Value::as_str) == Some(uid.as_str())) {
            let current_enabled = !matches!(items[index].get("enabled"), Some(Value::Bool(false)));
            if text_of(&items[index], "name") != *name || current_enabled != *enabled {
                if let Some(object) = items[index].as_object_mut() {
                    object.insert("name".to_string(), json!(name));
                    object.insert("enabled".to_string(), json!(enabled));
                    object.insert("updatedAt".to_string(), json!(now));
                }
                changes += 1;
            }
        } else {
            items.insert(0, json!({
                "id": new_id(),
                "name": name,
                "source": "clash",
                "listenerUid": uid,
                "enabled": enabled,
                "createdAt": now,
                "updatedAt": now,
                "lastTest": Value::Null,
            }));
            changes += 1;
        }
    }
    // 只对成功读取的 Clash 集合做镜像对账，其他来源的历史记录不受影响。
    let before = items.len();
    let mut seen = std::collections::HashSet::new();
    items.retain(|item| {
        if !is_clash(item) { return true; }
        let Some(uid) = item.get("listenerUid").and_then(Value::as_str) else { return false; };
        targets.iter().any(|(target, _, _)| target == uid) && seen.insert(uid.to_string())
    });
    changes += before - items.len();
    if changes > 0 {
        if let Err(error) = write_items(&items) {
            return ClashSyncReport { changes: 0, error: Some(error) };
        }
        logging::log("[Proxies]", &format!("🔄 已同步 Clash Verge 出口（{changes} 项变更）"));
    }
    ClashSyncReport { changes, error: None }
}

pub struct TestOutcome {
    pub success: bool,
    pub ip: String,
    pub duration_ms: i64,
    pub error: Option<String>,
}

pub fn record_test(id: &str, result: &TestOutcome) -> Result<(), String> {
    let _guard = mutation_lock();
    let mut items = read_items();
    let index = supported_index(&items, id)?;
    let Some(object) = items[index].as_object_mut() else {
        return Err("代理条目形状异常".to_string());
    };
    object.insert("lastTest".to_string(), json!({
        "success": result.success,
        "ip": result.ip,
        "durationMs": result.duration_ms,
        "at": logging::now_ms(),
        "error": result.error,
    }));
    write_items(&items)?;
    Ok(())
}

fn is_subscription_item(item: &Value) -> bool {
    text_of(item, "source") == "subscription"
}

pub fn prune_orphan_subscription_items(
    live_provider_ids: &std::collections::HashSet<String>,
) -> Result<usize, String> {
    let _guard = mutation_lock();
    let mut items = read_items();
    let before = items.len();
    items.retain(|item| {
        if !is_subscription_item(item) {
            return true;
        }
        item.get("providerId")
            .and_then(Value::as_str)
            .map(|provider_id| live_provider_ids.contains(provider_id))
            .unwrap_or(false) // 没有归属信息的坏行（手工改库）：清掉
    });
    let changes = before - items.len();
    if changes > 0 {
        write_items(&items)?;
    }
    Ok(changes)
}

/// 删除一条订阅节点的**孤儿**条目（所属订阅已不存在）。
///
/// 只服务「手动清理」这一条出路：正常路径下订阅删除 / 禁用后条目会随
/// 同步自动摘掉（见 `sync_subscription_nodes`），孤儿只出现在数据被外部
/// 工具清掉的场景（例如旧版进程误删 `subscriptions` 存储键 —— 实测踩过）：
/// 那时条目归属的订阅已经不存在，任何同步都不会再碰它，界面上需要一条
/// 手动删掉它的路。仍然拒绝 clash 条目与手动条目 —— 它们不属于订阅，
/// 不能借这个入口绕过各自的只读 / 正常写路径。
///
/// **是否孤儿由调用方（api 层）判定**：本模块不认识订阅存储（依赖方向
/// 是 subscriptions/sub_kernel → proxy_pool），只认「source == subscription」
/// 这一个形状约束。
pub fn remove_subscription_orphan(id: &str) -> Result<(Vec<Value>, String), String> {
    let _guard = mutation_lock();
    let mut items = read_items();
    let Some(index) = items
        .iter()
        .position(|item| item.get("id").and_then(Value::as_str) == Some(id))
    else {
        return Err(format!("代理「{id}」不存在"));
    };
    if !is_subscription_item(&items[index]) {
        return Err("仅可通过此入口清理孤儿订阅节点".to_string());
    }
    let removed = items.remove(index);
    write_items(&items)?;
    let name = text_of(&removed, "name");
    logging::log(
        "[Proxies]",
        &format!("🗑️ 删除订阅节点「{name}」（所属订阅已不存在，手动清理）"),
    );
    Ok((list(), name))
}

// ─── 订阅节点同步（全量镜像，内核拉到订阅后调用）─────────────

/// 一个待镜像的订阅节点（`core::sub_kernel` 在 provider 同步后构造）。
///
/// 定义在**本模块**而不是 sub_kernel：依赖方向是 sub_kernel → proxy_pool
/// （内核把节点写进来），反向会让两个模块成环 —— 订阅条目的端口存在条目
/// 自身里，本模块的解析（`resolve_item`）不需要回查内核。
pub struct SubscriptionNodeTarget {
    /// 订阅 id（与 `core::subscriptions` 条目的 id 一致；同步定位条目用它）
    pub provider_id: String,
    /// 订阅名（条目名的前半段）
    pub sub_name: String,
    /// 节点名（条目名的后半段；同时是内核配置里监听器绑定的出口名）
    pub node: String,
    /// 内核监听端口；**None = 未分配**（lazy listeners：只为账号或服务线路引用的
    /// 节点开监听器，未引用的节点仍镜像进池供浏览选择，端口为空 —— 引用后
    /// 由对账链路触发内核重启补上，见 `api::proxies::reconcile_listeners`）
    pub port: Option<u16>,
}

/// 把订阅节点集合整体镜像进池（与 `sync_clash` 同一套只读镜像语义）：
///
///   · 集合里的节点 upsert（按 `providerId + node` 定位：**已存在的沿用 id**
///     —— 账号按 id 引用池条目，重生成 id 会让引用全部悬空）；
///   · 订阅侧已消失的（或订阅被删 / 被禁用后不再出现在集合里的）镜像条目摘掉；
///   · manual 与 clash 条目从不被碰。
///
/// 返回变更条数（「已是最新」时为 0）。注意目标集合是**全部启用订阅的全部
/// 节点**：只传一条订阅的节点时，其它订阅的条目会被当作「已消失」摘掉
/// （调用方要传全量 —— sub_kernel 的同步总是构造全量）。
pub fn sync_subscription_nodes(targets: &[SubscriptionNodeTarget]) -> Result<usize, String> {
    let _guard = mutation_lock();
    let now = logging::now_ms();
    let mut items = read_items();
    let mut changes = 0usize;

    // ① 目标集合逐条 upsert（沿用已有条目的 id / createdAt / lastTest）
    for target in targets {
        let name = if target.sub_name.is_empty() {
            target.node.clone()
        } else {
            format!("{} · {}", target.sub_name, target.node)
        };
        let existing = items.iter_mut().position(|item| {
            is_subscription_item(item)
                && item.get("providerId").and_then(Value::as_str) == Some(target.provider_id.as_str())
                && item.get("node").and_then(Value::as_str) == Some(target.node.as_str())
        });
        match existing {
            Some(index) => {
                let current_port = items[index].get("port").and_then(Value::as_u64).map(|v| v as u16);
                let port_changed = current_port != target.port;
                let name_changed = text_of(&items[index], "name") != name;
                if port_changed || name_changed {
                    if let Some(object) = items[index].as_object_mut() {
                        object.insert("name".to_string(), Value::String(name));
                        // None = 未分配端口（lazy listeners）：写 null 而不是删键，
                        // 前端按 null 显示「未分配」
                        object.insert(
                            "port".to_string(),
                            target.port.map(|port| Value::from(port)).unwrap_or(Value::Null),
                        );
                        object.insert("updatedAt".to_string(), Value::from(now));
                    }
                    changes += 1;
                }
            }
            None => {
                items.insert(
                    0,
                    json!({
                        "id": new_id(),
                        "name": name,
                        "source": "subscription",
                        "providerId": target.provider_id,
                        "node": target.node,
                        "enabled": true,
                        // None = 未分配（lazy listeners，见 SubscriptionNodeTarget.port）
                        "port": target.port.map(|port| Value::from(port)).unwrap_or(Value::Null),
                        "createdAt": now,
                        "updatedAt": now,
                        "lastTest": Value::Null,
                    }),
                );
                changes += 1;
            }
        }
    }

    // ② 目标集合之外（且 providerId 不在集合里）的订阅镜像条目摘掉。
    //
    // 判据刻意按 **providerId** 而不是节点名：节点名随订阅内容变化（机场
    // 改名很常见），按名判定会把改名后的节点删了重加（id 变了，账号引用
    // 悬空）。providerId 不在本次集合 = 该订阅被删 / 被禁用 / 已无节点，
    // 它名下的全部条目才真正该走。
    let live_providers: std::collections::HashSet<&str> = targets
        .iter()
        .map(|target| target.provider_id.as_str())
        .collect();
    let before = items.len();
    items.retain(|item| {
        if !is_subscription_item(item) {
            return true;
        }
        let Some(provider_id) = item.get("providerId").and_then(Value::as_str) else {
            return false; // 没有引用信息的坏行（手工改库），清掉
        };
        live_providers.contains(provider_id)
    });
    changes += before - items.len();

    // 保留暂时消失节点的稳定引用，但不能继续暴露上一次内核的监听端口。
    // 否则订阅更新后端口已回收，仍可能被解析成可用代理甚至指向另一进程。
    let live_nodes: std::collections::HashSet<(&str, &str)> = targets.iter()
        .map(|target| (target.provider_id.as_str(), target.node.as_str())).collect();
    for item in &mut items {
        if !is_subscription_item(item) { continue; }
        let key = (item["providerId"].as_str().unwrap_or(""), item["node"].as_str().unwrap_or(""));
        if !live_nodes.contains(&key) && !item["port"].is_null() {
            item["port"] = Value::Null;
            item["updatedAt"] = json!(now);
            changes += 1;
        }
    }

    if changes > 0 {
        write_items(&items)?;
    }
    Ok(changes)
}

/// 把**全部订阅镜像条目**的端口清空（删内核时调用，见
/// `sub_kernel` worker 的 Remove 分支）。
///
/// ── 为什么清端口而不是把条目摘掉 ────────────────────────────
/// `sync_subscription_nodes(&[])` 会把订阅镜像整批摘掉，但重装内核后重新镜像
/// 出来的是**新 id**（`new_id()`），账号里存的旧 id 就永久悬空了 —— 用户只是
/// 删了个内核，回头再装上却发现所有引用订阅节点的账号都解析不出来，得逐个重配。
/// 端口置空的语义反而更准：节点还在（订阅还在），只是**这一轮没有监听器**，
/// 与 lazy listeners 的「未分配端口」是同一个状态；重装内核后同步按
/// `providerId + node` 命中同一条，端口原位写回，账号引用自然复活。
///
/// 保留 `lastTest`（历史读数，重启换端口后同样会留存）。返回变更条数。
pub fn unprovision_subscription_nodes() -> Result<usize, String> {
    let _guard = mutation_lock();
    let now = logging::now_ms();
    let mut items = read_items();
    let mut changes = 0usize;
    for item in items.iter_mut() {
        if !is_subscription_item(item) || valid_port(item.get("port")).is_none() {
            continue;
        }
        let Some(object) = item.as_object_mut() else { continue };
        object.insert("port".to_string(), Value::Null);
        object.insert("updatedAt".to_string(), Value::from(now));
        changes += 1;
    }
    if changes > 0 {
        write_items(&items)?;
    }
    Ok(changes)
}

/// 被引用的订阅节点键集合（`<订阅id>::<节点名>`，与内核端口注册表的键同一形态）。
///
/// `pool_ids` 是账号与服务线路的池引用合集（`usage::referenced_pool_ids`）。id 不在池里
/// 的引用（条目已被删）查不出节点、自然跳过 —— 那类引用解析时本来就会报「不存在」。
/// 内核的 `allocate_listeners` 用它决定「哪些节点开监听器」（lazy listeners）。
///
/// **本页禁用中的条目不算**（`is_enabled`）：账号虽然还引用着它，但引用解析已经
/// 按「已禁用」失败并回退直连了（见 `resolve_reference`）—— 再给它开着监听端口
/// 就是为一条没人用的节点白占端口，也与用户在启用列上按下的那一下自相矛盾。
pub fn subscription_node_keys(pool_ids: &std::collections::HashSet<&str>) -> std::collections::HashSet<String> {
    read_items()
        .iter()
        .filter(|item| is_subscription_item(item) && is_enabled(item))
        .filter(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .map(|id| pool_ids.contains(id))
                .unwrap_or(false)
        })
        .filter_map(|item| {
            let provider_id = item.get("providerId").and_then(Value::as_str)?;
            let node = item.get("node").and_then(Value::as_str)?;
            Some(format!("{provider_id}::{node}"))
        })
        .collect()
}

/// 内核该给哪些节点开监听器：**账号或服务线路引用中的条目**（禁用中的不算）。
///
/// 内核侧（`runtime::listener_node_keys`）与对账判定
/// （`api::proxies::reconcile_listeners`）都从这一处取，必须同一口径
/// —— 口径不一致就会出现「判定说没有缺口、内核却不建」这类谁也解释不清的
/// 状态。测试不在此列（测试走统一测试口，不需要端口，见模块头）。
pub fn listener_node_keys(pool_ids: &std::collections::HashSet<&str>) -> std::collections::HashSet<String> {
    subscription_node_keys(pool_ids)
}

/// 测试目标（`api::proxies::pool_test` 读它）：条目的展示名与订阅节点的定位
/// 信息（manual / clash 条目的 `provider_id` / `node` 为空串 —— 它们不走内核）。
pub struct TestTarget {
    /// 条目展示名（测试结果与日志里标「测的是谁」）
    pub name: String,
    /// manual | clash | subscription
    pub source: String,
    /// 订阅 id（订阅节点定位内核里的节点用）
    pub provider_id: String,
    /// 节点名（同上）
    pub node: String,
}

/// 找一条池条目作为测试目标（不存在报错）。
pub fn test_target(id: &str) -> Result<TestTarget, String> {
    let Ok(item) = find_raw(id) else {
        return Err(format!("代理「{id}」不存在或已被删除"));
    };
    Ok(TestTarget {
        name: display_name(&item, id),
        source: text_of(&item, "source"),
        provider_id: text_of(&item, "providerId"),
        node: text_of(&item, "node"),
    })
}

/// 这条订阅条目现在**需要监听器却没有端口**吗（启用后要不要补建的判据）。
///
/// 判据与 `listener_node_keys` 完全同口径（账号或服务线路引用，禁用中的不算），
/// 只是限定到一条：订阅条目已启用、端口还空着，并且在 `referenced` 引用合集里。
///
/// 与内核侧同口径是硬要求：口径不一致就会出现「判定说没有缺口、内核却不建」
/// 这类谁也解释不清的状态（补建那条链的注释里也写着同一句话）。
pub fn needs_listener(id: &str, referenced: &std::collections::HashSet<&str>) -> bool {
    let Ok(item) = find_raw(id) else {
        return false;
    };
    if !is_subscription_item(&item) || !is_enabled(&item) {
        return false;
    }
    if valid_port(item.get("port")).is_some() {
        return false;
    }
    referenced.contains(id)
}

/// 列出池里订阅节点的**端口状态**（`{providerId, node, port}`，`port` 为
/// null 表示未分配）。
///
/// 对账链路（`api::proxies::reconcile_listeners`）的读入口：拿它和「该开
/// 监听器的节点集合」（`listener_node_keys`）比对 —— 该开却没端口的要补建，
/// 端口还挂着却不该开的要回收。`provider_nodes`（provider 缓存）里没有的
/// 节点跳过 —— 订阅还没拉到内容时谈不上补建。
pub fn subscription_entries_with_ports() -> Vec<(String, String, Option<u16>)> {
    read_items()
        .iter()
        .filter(|item| is_subscription_item(item))
        .filter_map(|item| {
            let provider_id = item.get("providerId").and_then(Value::as_str)?.to_string();
            let node = item.get("node").and_then(Value::as_str)?.to_string();
            let port = item.get("port").and_then(Value::as_u64).map(|v| v as u16);
            Some((provider_id, node, port))
        })
        .collect()
}
