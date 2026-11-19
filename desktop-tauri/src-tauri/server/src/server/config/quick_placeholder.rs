use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const KEY: &str = "quickPlaceholder";

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub min_seconds: u64,
    pub max_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self { Self { enabled: true, min_seconds: 1, max_seconds: 5 } }
}

pub fn validate(value: &Value) -> Result<Settings, String> {
    let settings: Settings = serde_json::from_value(value.clone())
        .map_err(|_| "占位设置需要 enabled、minSeconds 和 maxSeconds".to_string())?;
    if settings.max_seconds > 120 || settings.min_seconds > settings.max_seconds {
        return Err("占位等待时间应为 0–120 秒，且下限不能大于上限".to_string());
    }
    Ok(settings)
}

pub fn current() -> Settings {
    super::with_raw(|raw| raw.get(KEY).and_then(|value| validate(value).ok()).unwrap_or_default())
        .unwrap_or_default()
}

pub fn save(settings: Settings) -> Result<(), String> {
    super::try_update_raw_field(KEY, |value| {
        *value = serde_json::to_value(settings).expect("serializable settings");
        Ok(())
    }, || "占位设置保存失败".to_string())
}

pub fn delay(settings: Settings) -> std::time::Duration {
    let min = settings.min_seconds * 1000;
    let span = (settings.max_seconds - settings.min_seconds) * 1000 + 1;
    let mut bytes = [0u8; 8];
    let offset = if getrandom::getrandom(&mut bytes).is_ok() { u64::from_le_bytes(bytes) % span } else { 0 };
    std::time::Duration::from_millis(min + offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_switch_and_random_or_fixed_range() {
        for enabled in [true, false] {
            let value = serde_json::json!({"enabled":enabled,"minSeconds":2,"maxSeconds":2});
            let settings = validate(&value).unwrap();
            assert_eq!(delay(settings), std::time::Duration::from_secs(2));
        }
        for value in [serde_json::json!({"enabled":true,"minSeconds":6,"maxSeconds":5}),
            serde_json::json!({"enabled":true,"minSeconds":0,"maxSeconds":121}),
            serde_json::json!({"enabled":true,"minSeconds":-1,"maxSeconds":5})] {
            assert!(validate(&value).is_err());
        }
        for _ in 0..100 { assert!((1000..=5000).contains(&delay(Settings::default()).as_millis())); }
    }
}
