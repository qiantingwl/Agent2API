//! Temporary mutual exclusion with native provider RPCs; never changes account switches.
use std::{collections::HashMap, sync::{Arc, Mutex, OnceLock}};
use tokio::sync::{RwLock, OwnedRwLockReadGuard, OwnedRwLockWriteGuard};
use crate::server::errors::GatewayError;

type Locks = Mutex<HashMap<String, Arc<RwLock<()>>>>;
static LOCKS: OnceLock<Locks> = OnceLock::new();
type Leases = Mutex<HashMap<String, (String, OwnedRwLockWriteGuard<()>)>>;
static LEASES: OnceLock<Leases> = OnceLock::new();
fn lock(account: &str) -> Arc<RwLock<()>> {
    LOCKS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
        .entry(account.to_string()).or_default().clone()
}
pub fn supported(provider: &str) -> bool { matches!(provider, "loomy" | "raccoon" | "codearts" | "wps-lingxi") }
pub async fn native(provider: &str, account: &str) -> Result<Option<OwnedRwLockReadGuard<()>>, GatewayError> {
    if account.is_empty() || !supported(provider) { return Ok(None); }
    tokio::time::timeout(std::time::Duration::from_secs(60), lock(account).read_owned()).await
        .map(Some).map_err(|_| GatewayError::with_status(503, "独立维护正在同步凭证，请稍后重试").with_code("external_maintenance_busy"))
}
pub fn acquire(account: &str, owner: &str) -> bool {
    let mut leases = LEASES.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    if let Some((existing, _)) = leases.get(account) { return existing == owner; }
    let Ok(guard) = lock(account).try_write_owned() else { return false; };
    leases.insert(account.into(), (owner.into(), guard));
    let account = account.to_string(); let owner = owner.to_string();
    crate::spawn_task(async move {
        tokio::time::sleep(std::time::Duration::from_secs(180)).await;
        release(&account, &owner);
    });
    true
}
pub fn release(account: &str, owner: &str) -> bool {
    let mut leases = LEASES.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    if leases.get(account).is_some_and(|(existing, _)| existing == owner) {
        leases.remove(account); return true;
    }
    false
}
