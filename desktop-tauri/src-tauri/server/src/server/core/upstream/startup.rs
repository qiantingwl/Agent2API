//! Shared output recognition for downstream placeholders and replay safety.
//! Provider waiting, retries, and deadlines remain in the official forwarding flow.
use serde_json::Value;

pub(in crate::server) fn effective_output(frame: &Value) -> bool {
    frame.get("choices").and_then(Value::as_array).is_some_and(|choices| choices.iter().any(|c| {
        let delta = c.get("delta").or_else(|| c.get("message"));
        delta.is_some_and(|d| ["content", "reasoning_content", "reasoning", "tool_calls", "function_call"].iter().any(|key| {
            match d.get(*key) {
                Some(Value::String(s)) => !s.trim().is_empty(),
                Some(Value::Array(a)) => !a.is_empty(),
                Some(Value::Object(o)) => !o.is_empty(),
                _ => false,
            }
        }))
    }))
}
