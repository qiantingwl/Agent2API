//! Loomy / 小浣熊 / WPS 换号共用首段预算；保活、空白和角色帧不算有效输出。
use std::{sync::Arc, time::Duration};
use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt};
use serde_json::Value;
use tokio::time::Instant;
use crate::server::{config, errors::GatewayError};
use super::{cancellation, refusal::HeldHead, stall, usage::RequestTelemetry};
const MAX_PREFIX: usize = 256 * 1024;

pub(super) fn applies_to(providers: &[String], has_images: bool) -> bool {
    !has_images && !providers.is_empty()
        && providers.iter().all(|p| matches!(p.as_str(), "loomy" | "raccoon" | "wps-lingxi"))
}

// 仅在尚未向调用方释放有效输出、总预算仍有余额时允许换号。
pub(super) fn retryable_before_output(error: &GatewayError, deadline: Instant) -> bool {
    Instant::now() < deadline
        && matches!(error.code.as_deref(), Some("empty_response" | "upstream_startup_connection"))
}

pub(super) fn timeout_error() -> GatewayError {
    GatewayError::with_status(504, "首次有效输出等待预算已耗尽（所有换号尝试共用）")
        .with_code("upstream_startup_timeout")
}

fn useful(frame: &Value) -> bool {
    if frame.get("error").is_some_and(|e| !e.is_null()) { return true; }
    effective_output(frame) || frame.get("choices").and_then(Value::as_array)
        .is_some_and(|cs| cs.iter().any(|c| c.get("finish_reason").and_then(Value::as_str) == Some("content_filter")))
}

pub(super) fn effective_output(frame: &Value) -> bool {
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

/// Includes plugin preparation and nonstream aggregation. Real output releases
/// only the startup deadline; existing provider completion limits still apply.
pub(super) async fn await_outcome<F>(forward: F, deadline: Instant, telemetry: &Arc<RequestTelemetry>)
    -> Result<super::ForwardOutcome, GatewayError>
where F: std::future::Future<Output = Result<super::ForwardOutcome, GatewayError>> {
    tokio::pin!(forward);
    match tokio::time::timeout_at(deadline, &mut forward).await {
        Ok(result) => result,
        Err(_) if telemetry.effective_output_before(deadline) => forward.await,
        Err(_) => Err(timeout_error()),
    }
}

pub(super) async fn hold_outcome<F>(forward: F, deadline: Instant, telemetry: &Arc<RequestTelemetry>)
    -> Result<super::ForwardOutcome, GatewayError>
where F: std::future::Future<Output = Result<super::ForwardOutcome, GatewayError>> {
    let outcome = await_outcome(forward, deadline, telemetry).await?;
    match outcome {
        super::ForwardOutcome::Stream { status, stream } => {
            let waiting = hold_source(Box::pin(stream), deadline);
            let (prefix, rest) = if let Some(token) = telemetry.cancel_token() {
                tokio::select! {
                    result = waiting => result?,
                    _ = token.cancelled() => return Err(cancellation::cancelled_error()),
                }
            } else { waiting.await? };
            let joined = futures::stream::once(async move { Ok(Bytes::from(prefix)) }).chain(rest);
            Ok(super::ForwardOutcome::Stream { status, stream: Box::new(Box::pin(joined)) })
        }
        other => Ok(other),
    }
}

fn prefix_ready(bytes: &[u8]) -> bool {
    // Only complete data lines count, even when UTF-8/JSON are split across chunks.
    let text = String::from_utf8_lossy(bytes);
    for line in text.split_inclusive('\n').filter(|line| line.ends_with('\n')) {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else { continue; };
        if data == "[DONE]" { return false; }
        if let Ok(v) = serde_json::from_str::<Value>(data) {
            if useful(&v) { return true; }
            // 终帧在前时，不能用后面的异常残留数据把空回答判成成功。
            if v.get("choices").and_then(Value::as_array).is_some_and(|cs| cs.iter().any(|c|
                c.get("finish_reason").and_then(Value::as_str).is_some_and(|s| !s.is_empty()))) {
                return false;
            }
        }
    }
    false
}

fn terminal_without_output(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).split_inclusive('\n').filter(|line| line.ends_with('\n')).any(|line| {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else { return false; };
        data == "[DONE]" || serde_json::from_str::<Value>(data).ok().is_some_and(|v|
            v.get("choices").and_then(Value::as_array).is_some_and(|cs| cs.iter().any(|c|
                c.get("finish_reason").and_then(Value::as_str).is_some_and(|s| !s.is_empty()))))
    })
}

async fn hold_source(mut source: BoxStream<'static, Result<Bytes, std::io::Error>>, deadline: Instant)
    -> Result<(Vec<u8>, BoxStream<'static, Result<Bytes, std::io::Error>>), GatewayError> {
    let mut buffered = Vec::new();
    loop {
        let item = tokio::time::timeout_at(deadline, source.next()).await.map_err(|_| timeout_error())?;
        match item {
            Some(Ok(chunk)) => {
                if buffered.len().saturating_add(chunk.len()) > MAX_PREFIX {
                    return Err(GatewayError::with_status(502, "上游首段数据超过核验缓冲上限"));
                }
                buffered.extend_from_slice(&chunk);
                if let Some(error) = error_before_output(&buffered) { return Err(error); }
                if prefix_ready(&buffered) { return Ok((buffered, source)); }
                if terminal_without_output(&buffered) {
                    return Err(GatewayError::with_status(502, "上游结束但没有有效输出").with_code("empty_response"));
                }
            }
            Some(Err(error)) => return Err(GatewayError::with_status(502, format!("首次有效输出前连接中断: {error}"))
                .with_code("upstream_startup_connection")),
            None => return Err(GatewayError::with_status(502, "上游在有效输出前结束响应").with_code("empty_response")),
        }
    }
}

fn error_before_output(bytes: &[u8]) -> Option<GatewayError> {
    for line in String::from_utf8_lossy(bytes).split_inclusive('\n').filter(|line| line.ends_with('\n')) {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else { continue };
        if data == "[DONE]" { return None; }
        let Ok(frame) = serde_json::from_str::<Value>(data) else { continue };
        // Preserve ordering: an earlier effective frame irrevocably releases the stream.
        if let Some(error) = frame.get("error").filter(|error| !error.is_null()) {
            let status = error.get("status").or_else(|| error.get("statusCode")).and_then(Value::as_i64)
                .filter(|status| (400..600).contains(status)).unwrap_or(502) as i32;
            let mut failure = GatewayError::with_status(status,
                error.get("message").and_then(Value::as_str).or_else(|| error.as_str()).unwrap_or("上游在有效输出前返回错误"));
            failure.code = error.get("code").and_then(Value::as_str).map(str::to_string);
            return Some(failure);
        }
        if effective_output(&frame) { return None; }
    }
    None
}

pub(super) async fn hold_response(response: reqwest::Response, deadline: Instant, telemetry: &Arc<RequestTelemetry>) -> Result<HeldHead, GatewayError> {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let inner = response.bytes_stream().map(|item| item.map_err(|e| std::io::Error::other(crate::server::core::egress::describe_error_detail(&e))));
    let source = stall::idle_guard(Box::pin(inner), Duration::from_millis(config::timeout_settings().stream_idle_ms()));
    let waiting = hold_source(source, deadline);
    let (buffered, rest) = if let Some(token) = telemetry.cancel_token() {
        tokio::select! {
            result = waiting => result?,
            _ = token.cancelled() => return Err(cancellation::cancelled_error()),
        }
    } else { waiting.await? };
    Ok(HeldHead { status, headers, buffered, rest, finish_reason: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fragmented_error_before_output_preserves_classification() {
        let source = futures::stream::iter([
            b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\" \"}}]}\n\n".as_slice(),
            b"data: {\"error\":{\"status\":429,\"code\":\"rate_limit\",",
            b"\"message\":\"retry later\"}}\n\n",
        ].into_iter().map(|bytes| Ok(Bytes::copy_from_slice(bytes))));
        let error = hold_source(Box::pin(source), Instant::now()+Duration::from_secs(1)).await.err().unwrap();
        assert_eq!(error.status_code, 429);
        assert_eq!(error.code.as_deref(), Some("rate_limit"));
        assert_eq!(error.message, "retry later");
    }

    #[tokio::test]
    async fn error_after_effective_output_is_preserved_without_replay() {
        for delta in [serde_json::json!({"content":"partial"}), serde_json::json!({"reasoning_content":"thinking"}),
            serde_json::json!({"tool_calls":[{"id":"call"}]})] {
            let bytes = format!("data: {}\n\ndata: {{\"error\":{{\"status\":429,\"message\":\"late error\"}}}}\n\n",
                serde_json::json!({"choices":[{"delta":delta}]})).into_bytes();
            let source = futures::stream::iter([Ok(Bytes::copy_from_slice(&bytes))]);
            let (prefix, _) = hold_source(Box::pin(source), Instant::now()+Duration::from_secs(1)).await.unwrap();
            assert_eq!(prefix, bytes);
        }
    }

    #[tokio::test]
    async fn plugin_nonstream_output_releases_startup_deadline() {
        let telemetry = Arc::new(RequestTelemetry::new());
        let observed = telemetry.clone();
        let deadline = Instant::now() + Duration::from_millis(30);
        let forward = async move {
            observed.note_effective_output(&serde_json::json!({"choices":[{"delta":{"reasoning_content":"thinking"}}]}));
            tokio::time::sleep(Duration::from_millis(60)).await;
            Ok(super::super::ForwardOutcome::Completion { body: serde_json::json!({"answer":"complete"}) })
        };
        assert!(hold_outcome(forward, deadline, &telemetry).await.is_ok());
    }

    #[tokio::test]
    async fn plugin_role_only_does_not_release_deadline() {
        let telemetry = Arc::new(RequestTelemetry::new());
        telemetry.note_effective_output(&serde_json::json!({"choices":[{"delta":{"role":"assistant","content":" "}}]}));
        let result = hold_outcome(futures::future::pending(), Instant::now()+Duration::from_millis(10), &telemetry).await;
        assert_eq!(result.err().unwrap().code.as_deref(), Some("upstream_startup_timeout"));
    }

    #[tokio::test]
    async fn plugin_stream_keeps_late_content_after_first_output() {
        let telemetry = Arc::new(RequestTelemetry::new());
        let stream = futures::stream::iter([Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n"))])
            .chain(futures::stream::once(async { tokio::time::sleep(Duration::from_millis(30)).await; Ok(Bytes::from_static(b"late")) }));
        let forward = async { Ok(super::super::ForwardOutcome::Stream {status:200,stream:Box::new(Box::pin(stream))}) };
        let outcome = hold_outcome(forward, Instant::now()+Duration::from_millis(10), &telemetry).await.unwrap();
        let super::super::ForwardOutcome::Stream {mut stream,..} = outcome else { panic!("expected stream") };
        assert!(stream.next().await.unwrap().is_ok());
        assert_eq!(stream.next().await.unwrap().unwrap(), Bytes::from_static(b"late"));
    }

    #[test]
    fn role_and_heartbeat_are_not_output() {
        assert!(!prefix_ready(b": heartbeat\n\ndata: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n"));
        assert!(prefix_ready(b"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking\"}}]}\n\n"));
        assert!(prefix_ready(b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"t\"}]}}]}\n\n"));
        assert!(!prefix_ready(b"data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}"));
    }
    #[tokio::test]
    async fn empty_terminal_is_error_but_usage_is_not_required() {
        for payload in [b"data: [DONE]\n\n".as_slice(),b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"] {
            let source=futures::stream::iter([Ok(Bytes::copy_from_slice(payload))]);
            assert!(hold_source(Box::pin(source),Instant::now()+Duration::from_secs(1)).await.is_err());
        }
        assert!(prefix_ready(b"data: {\"choices\":[{\"delta\":{\"content\":\"reply\"}}]}\n\n"));
    }
    #[tokio::test]
    async fn pending_stream_expires_without_new_attempt_budget() {
        let deadline=Instant::now()+Duration::from_millis(20);
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(hold_source(Box::pin(futures::stream::pending()),deadline).await.is_err());
        assert!(Instant::now() >= deadline);
    }
    #[tokio::test]
    async fn content_releases_deadline_and_preserves_late_answer() {
        let source=futures::stream::iter([Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"))])
            .chain(futures::stream::once(async {tokio::time::sleep(Duration::from_millis(30)).await;Ok(Bytes::from_static(b"later"))}));
        let (prefix,mut rest)=hold_source(Box::pin(source),Instant::now()+Duration::from_millis(10)).await.unwrap();
        assert!(prefix_ready(&prefix));assert_eq!(rest.next().await.unwrap().unwrap(),Bytes::from_static(b"later"));
    }
    #[tokio::test]
    async fn fragmented_json_and_heartbeat_preserved() {
        let source=futures::stream::iter([b": hi\n\n".as_slice(),b"data: {\"choices\":[{\"delta\":{\"content\":\"he",b"llo\"}}]}\n\n"].into_iter().map(|b|Ok(Bytes::copy_from_slice(b))));
        let (prefix,_)=hold_source(Box::pin(source),Instant::now()+Duration::from_secs(1)).await.unwrap();
        assert!(prefix.starts_with(b": hi"));assert!(prefix_ready(&prefix));
    }

    #[test]
    fn whitespace_and_null_error_do_not_release_wait_budget() {
        assert!(!prefix_ready(b"data: {\"choices\":[{\"delta\":{\"content\":\"\\n \",\"reasoning_content\":\"\\t\"}}],\"error\":null}\n\n"));
        assert!(prefix_ready(b"data: {\"choices\":[{\"delta\":{\"content\":\" answer\"}}],\"error\":null}\n\n"));
        assert!(prefix_ready(b"data: {\"error\":{\"message\":\"denied\"}}\n\n"));
        assert!(prefix_ready(b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"content_filter\"}]}\n\n"));
    }
    #[test]
    fn budget_scope_includes_raccoon_and_excludes_other_routes() {
        for ps in [vec!["loomy".into()],vec!["raccoon".into()],vec!["loomy".into(),"raccoon".into()]] {
            assert!(applies_to(&ps,false));assert!(!applies_to(&ps,true));
        }
        assert!(!applies_to(&[],false));
        assert!(applies_to(&["loomy".into(),"wps-lingxi".into()],false));
        assert!(!applies_to(&["codearts".into()],false));
    }
    #[tokio::test]
    async fn blank_only_terminal_and_eof_are_retryable_empty() {
        for tail in [Some(b"data: [DONE]\n\n".as_slice()),None] {
            let mut items=vec![Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"\\n\"}}]}\n\n"))];
            if let Some(t)=tail {items.push(Ok(Bytes::copy_from_slice(t)));}
            let deadline=Instant::now()+Duration::from_secs(1);
            let error=hold_source(Box::pin(futures::stream::iter(items)),deadline).await.err().unwrap();
            assert_eq!(error.code.as_deref(),Some("empty_response"));
            assert!(retryable_before_output(&error,deadline));
        }
    }
    #[tokio::test]
    async fn connection_failure_before_output_retries_with_remaining_budget_only() {
        let deadline=Instant::now()+Duration::from_secs(1);
        let source=futures::stream::iter([Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset,"synthetic reset"))]);
        let e=hold_source(Box::pin(source),deadline).await.err().unwrap();
        assert!(retryable_before_output(&e,deadline));
        assert!(!retryable_before_output(&e,Instant::now()));
        assert!(!retryable_before_output(&timeout_error(),deadline));
        assert!(!retryable_before_output(&GatewayError::with_status(401,"denied"),deadline));
    }
    #[tokio::test]
    async fn continuous_blank_heartbeat_does_not_extend_deadline() {
        let deadline=Instant::now()+Duration::from_millis(35);
        let source=futures::stream::unfold((),|()|async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Some((Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"\\n\"}}]}\n\n")),()))
        });
        let e=hold_source(Box::pin(source),deadline).await.err().unwrap();
        assert_eq!(e.code.as_deref(),Some("upstream_startup_timeout"));
    }
    #[tokio::test]
    async fn empty_account_then_good_account_keeps_one_deadline() {
        let deadline=Instant::now()+Duration::from_millis(80);
        let empty=futures::stream::once(async {tokio::time::sleep(Duration::from_millis(10)).await;Ok(Bytes::from_static(b"data: [DONE]\n\n"))});
        let e=hold_source(Box::pin(empty),deadline).await.err().unwrap();
        assert!(retryable_before_output(&e,deadline));
        let good=futures::stream::iter([Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\n"))]);
        assert!(hold_source(Box::pin(good),deadline).await.is_ok());
        tokio::time::sleep_until(deadline).await;
        assert!(!retryable_before_output(&e,deadline));
    }
    #[tokio::test]
    async fn downstream_placeholder_can_arrive_while_upstream_still_waits() {
        // 模拟外层已有占位：它不受内层等待保护阻塞，也不会解除内层预算。
        let source=futures::stream::once(async {tokio::time::sleep(Duration::from_millis(40)).await;Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\n"))});
        let waiting=hold_source(Box::pin(source),Instant::now()+Duration::from_secs(1));
        tokio::pin!(waiting);
        tokio::select! {
            _=tokio::time::sleep(Duration::from_millis(5))=>{},
            _=&mut waiting=>panic!("upstream released before effective output"),
        }
        assert!(waiting.await.is_ok());
    }
    #[test]
    fn terminal_before_content_cannot_become_success() {
        assert!(!prefix_ready(b"data: [DONE]\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"late\"}}]}\n\n"));
    }
    #[tokio::test]
    async fn reset_after_content_is_not_replayed_or_hidden() {
        let source=futures::stream::iter([
            Ok(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")),
            Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset,"synthetic reset"))]);
        let (prefix,mut rest)=hold_source(Box::pin(source),Instant::now()+Duration::from_secs(1)).await.unwrap();
        assert!(prefix_ready(&prefix));assert!(rest.next().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn real_http_blank_then_disconnect_is_empty() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        let server=tokio::spawn(async move {
            let (mut socket,_)=listener.accept().await.unwrap();let mut request=[0u8;2048];
            socket.read(&mut request).await.unwrap();
            let body=b"data: {\"choices\":[{\"delta\":{\"content\":\"\\n\"}}],\"error\":null}\n\n";
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
        });
        let response=reqwest::Client::new().get(format!("http://{addr}/mock")).send().await.unwrap();
        // 使用实际 reqwest 字节流，确认不是只测 JSON 判据。
        let source=response.bytes_stream().map(|r|r.map(|b| Bytes::copy_from_slice(&b)).map_err(std::io::Error::other));
        let e=hold_source(Box::pin(source),Instant::now()+Duration::from_secs(1)).await.err().unwrap();
        assert_eq!(e.code.as_deref(),Some("empty_response"));server.await.unwrap();
    }
    #[tokio::test]
    async fn real_http_placeholder_waits_for_content_then_preserves_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
        let blank=b"data: {\"choices\":[{\"delta\":{\"content\":\"\\n\"}}]}\n\n";
        let answer=b"data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\ndata: [DONE]\n\n";
        let server=tokio::spawn(async move {
            let (mut socket,_)=listener.accept().await.unwrap();let mut request=[0u8;2048];socket.read(&mut request).await.unwrap();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",blank.len()+answer.len()).as_bytes()).await.unwrap();
            socket.write_all(blank).await.unwrap();tokio::time::sleep(Duration::from_millis(60)).await;
            socket.write_all(answer).await.unwrap();
        });
        let response=reqwest::Client::new().get(format!("http://{addr}/mock")).send().await.unwrap();
        let source=response.bytes_stream().map(|r|r.map(|b| Bytes::copy_from_slice(&b)).map_err(std::io::Error::other));
        let waiting=hold_source(Box::pin(source),Instant::now()+Duration::from_secs(1));tokio::pin!(waiting);
        tokio::select!{_=tokio::time::sleep(Duration::from_millis(5))=>{},_=&mut waiting=>panic!("blank released the guard"),}
        let (mut data,mut rest)=waiting.await.unwrap();while let Some(c)=rest.next().await {data.extend_from_slice(&c.unwrap());}
        assert_eq!(data,[blank.as_slice(),answer.as_slice()].concat());server.await.unwrap();
    }
}
