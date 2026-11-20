//! Validate the first useful upstream output before handing the stream away.
//! Downstream placeholders do not commit an account. No cross-attempt deadline is added.
use std::{sync::Arc, time::Duration};
use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt};
use serde_json::Value;
use crate::server::{config, errors::GatewayError};
use super::{cancellation, refusal::HeldHead, stall, usage::RequestTelemetry};

const MAX_PREFIX: usize = 256 * 1024;

pub(super) fn applies_to(provider: &str) -> bool {
    matches!(provider, "loomy" | "raccoon" | "wps-lingxi")
}

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

enum Prefix { Waiting, Ready, Failed(GatewayError) }

fn inspect_prefix(bytes: &[u8]) -> Prefix {
    let text = String::from_utf8_lossy(bytes);
    let mut data = String::new();
    for line in text.split_inclusive('\n').filter(|line| line.ends_with('\n')) {
        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() { data.push('\n'); }
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
            continue;
        }
        if !line.is_empty() { continue; }
        if data.trim() == "[DONE]" { return Prefix::Failed(empty_error()); }
        if let Ok(frame) = serde_json::from_str::<Value>(&data) {
            if let Some(error) = frame.get("error").filter(|error| !error.is_null()) {
                let status = error.get("status").or_else(|| error.get("statusCode"))
                    .or_else(|| frame.get("status")).and_then(Value::as_i64)
                    .filter(|status| (400..600).contains(status)).unwrap_or(502) as i32;
                let mut failure = GatewayError::with_status(status,
                    error.get("message").and_then(Value::as_str).or_else(|| error.as_str())
                        .unwrap_or("上游在有效输出前返回错误"));
                failure.code = error.get("code").or_else(|| error.get("type"))
                    .and_then(|value| value.as_str().map(str::to_string)
                        .or_else(|| value.as_i64().map(|number| number.to_string())));
                return Prefix::Failed(failure);
            }
            if effective_output(&frame) { return Prefix::Ready; }
            // A policy refusal is an intentional terminal result, not an empty account.
            if frame.get("choices").and_then(Value::as_array).is_some_and(|choices|
                choices.iter().any(|choice| choice.get("finish_reason").and_then(Value::as_str) == Some("content_filter"))) {
                return Prefix::Ready;
            }
            if frame.get("choices").and_then(Value::as_array).is_some_and(|choices|
                choices.iter().any(|choice| choice.get("finish_reason").and_then(Value::as_str)
                    .is_some_and(|reason| !reason.is_empty()))) {
                return Prefix::Failed(empty_error());
            }
        }
        data.clear();
    }
    Prefix::Waiting
}

fn empty_error() -> GatewayError {
    GatewayError::with_status(502, "上游在有效输出前结束响应").with_code("empty_response")
}

async fn hold_source(mut source: BoxStream<'static, Result<Bytes, std::io::Error>>,
    telemetry: &Arc<RequestTelemetry>)
    -> Result<(Vec<u8>, BoxStream<'static, Result<Bytes, std::io::Error>>), GatewayError> {
    let mut prefix = Vec::new();
    loop {
        let item = if let Some(token) = telemetry.cancel_token() {
            tokio::select! {
                biased;
                _ = token.cancelled() => return Err(cancellation::cancelled_error()),
                item = source.next() => item,
            }
        } else { source.next().await };
        match item {
            Some(Ok(chunk)) => {
                // Inspect before enforcing the bound so a large first answer is not rejected.
                prefix.extend_from_slice(&chunk);
                match inspect_prefix(&prefix) {
                    Prefix::Ready => return Ok((prefix, source)),
                    Prefix::Failed(error) => return Err(error),
                    Prefix::Waiting if prefix.len() >= MAX_PREFIX => return Err(
                        GatewayError::with_status(502, "上游首段没有有效输出且超过缓冲上限")
                            .with_code("empty_response")),
                    Prefix::Waiting => {},
                }
            }
            Some(Err(error)) => return Err(GatewayError::with_status(502,
                format!("首次有效输出前连接中断: {error}")).with_code("upstream_startup_connection")),
            None => return Err(empty_error()),
        }
    }
}

pub(super) async fn hold_outcome(outcome: super::ForwardOutcome, telemetry: &Arc<RequestTelemetry>)
    -> Result<super::ForwardOutcome, GatewayError> {
    match outcome {
        super::ForwardOutcome::Stream { status, stream } => {
            let source = stall::idle_guard(Box::pin(stream),
                Duration::from_millis(config::timeout_settings().stream_idle_ms()));
            let (prefix, rest) = hold_source(source, telemetry).await?;
            let joined = futures::stream::once(async move { Ok(Bytes::from(prefix)) }).chain(rest);
            Ok(super::ForwardOutcome::Stream { status, stream: Box::new(Box::pin(joined)) })
        }
        other => Ok(other),
    }
}

pub(super) async fn hold_response(response: reqwest::Response, telemetry: &Arc<RequestTelemetry>)
    -> Result<HeldHead, GatewayError> {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let inner = response.bytes_stream().map(|item| item.map_err(|error|
        std::io::Error::other(crate::server::core::egress::describe_error_detail(&error))));
    let rest = stall::idle_guard(Box::pin(inner),
        Duration::from_millis(config::timeout_settings().stream_idle_ms()));
    hold_head(HeldHead { status, headers, buffered: Vec::new(), rest, finish_reason: None }, telemetry).await
}

pub(super) async fn hold_head(head: HeldHead, telemetry: &Arc<RequestTelemetry>) -> Result<HeldHead, GatewayError> {
    let HeldHead { status, headers, buffered, rest, finish_reason } = head;
    let source = futures::stream::once(async move { Ok(Bytes::from(buffered)) }).chain(rest);
    let (buffered, rest) = hold_source(Box::pin(source), telemetry).await?;
    Ok(HeldHead { status, headers, buffered, rest, finish_reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn blank_then_error_is_retryable_and_content_then_error_is_preserved() {
        let telemetry = Arc::new(RequestTelemetry::new());
        let source = futures::stream::iter([
            Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\" \"}}]}\n\n")),
            Ok(Bytes::from_static(b"data: {\"error\":{\"status\":429,\"code\":\"rate_limit\"}}\n\n")),
        ]);
        let error = hold_source(Box::pin(source), &telemetry).await.err().unwrap();
        assert_eq!(error.status_code, 429);
        assert_eq!(error.code.as_deref(), Some("rate_limit"));
        for delta in [serde_json::json!({"content":"answer"}), serde_json::json!({"reasoning_content":"thinking"}),
            serde_json::json!({"tool_calls":[{"id":"call"}]})] {
            let bytes = format!("data: {}\n\ndata: {{\"error\":{{\"status\":429}}}}\n\n",
                serde_json::json!({"choices":[{"delta":delta}]})).into_bytes();
            let source = futures::stream::iter([Ok(Bytes::from(bytes.clone()))]);
            assert_eq!(hold_source(Box::pin(source), &telemetry).await.unwrap().0, bytes);
        }
    }
    #[tokio::test]
    async fn empty_terminal_and_disconnect_fail_before_handoff() {
        let telemetry = Arc::new(RequestTelemetry::new());
        for bytes in [b"data: [DONE]\n\n".as_slice(), b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"] {
            let source = futures::stream::iter([Ok(Bytes::copy_from_slice(bytes))]);
            assert_eq!(hold_source(Box::pin(source), &telemetry).await.err().unwrap().code.as_deref(), Some("empty_response"));
        }
        let source = futures::stream::iter([Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset"))]);
        assert_eq!(hold_source(Box::pin(source), &telemetry).await.err().unwrap().code.as_deref(), Some("upstream_startup_connection"));
    }
    #[test]
    fn fragmented_events_wait_and_terminal_order_is_preserved() {
        assert!(matches!(inspect_prefix(b"data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n"), Prefix::Waiting));
        assert!(matches!(inspect_prefix(b"data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\r\n\r\n"), Prefix::Ready));
        assert!(matches!(inspect_prefix(b"data: [DONE]\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"late\"}}]}\n\n"), Prefix::Failed(_)));
    }
}
