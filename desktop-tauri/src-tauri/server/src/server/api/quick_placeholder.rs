//! Downstream acknowledgement. It never changes upstream output or replay permission.
use std::{future::Future, io};

use axum::{
    body::{Body, BodyDataStream, Bytes},
    http::{header, HeaderValue},
    response::Response,
};
use futures::{stream, StreamExt};
use serde_json::{json, Value};
use tokio::time::{sleep_until, Instant};

const MAX_PRELUDE: usize = 64 * 1024;

pub(super) async fn respond(
    model: String,
    deadline: Instant,
    response: impl Future<Output = Response> + Send + 'static,
) -> Response {
    let mut response = Box::pin(response);
    let response = tokio::select! {
        biased;
        ready = &mut response => ready,
        _ = sleep_until(deadline) => {
            return Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-cache")
                .header("X-Accel-Buffering", "no")
                .body(Body::from_stream(
                    stream::iter([Ok::<_, io::Error>(placeholder(&model))])
                        .chain(stream::once(async move { after_placeholder(response.await).await }).flatten()),
                ))
                .expect("constant SSE headers");
        }
    };
    if !is_sse(&response) {
        return response;
    }

    // A streaming response may have only headers, comments, or role frames so far.
    // Keep polling with the original deadline until useful content or a terminal frame arrives.
    let (mut parts, body) = response.into_parts();
    let mut body = body.into_data_stream();
    let mut prefix = Vec::new();
    let expired = tokio::select! {
        biased;
        _ = read_prelude(&mut body, &mut prefix) => false,
        _ = sleep_until(deadline) => true,
    };
    parts.headers.insert("X-Accel-Buffering", HeaderValue::from_static("no"));
    if expired {
        parts.headers.remove(header::CONTENT_LENGTH);
    }
    let first = expired.then(|| Ok::<_, axum::Error>(placeholder(&model)));
    let stream = stream::iter(first.into_iter().chain(prefix)).chain(body);
    Response::from_parts(parts, Body::from_stream(stream))
}

fn is_sse(response: &Response) -> bool {
    response.status().is_success()
        && response.headers().get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"))
}

fn placeholder(model: &str) -> Bytes {
    crate::server::core::protocol::chat_frame(&json!({
        "id": "chatcmpl-gateway-placeholder", "object": "chat.completion.chunk",
        "created": crate::server::logging::now_ms() / 1000, "model": model,
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": " "}, "finish_reason": null}]
    }))
}

async fn read_prelude(body: &mut BodyDataStream, prefix: &mut Vec<Result<Bytes, axum::Error>>) {
    let mut retained_bytes = 0;
    while let Some(item) = body.next().await {
        let ready = match &item {
            Ok(bytes) if bytes.is_empty() => continue,
            Ok(bytes) => {
                retained_bytes += bytes.len();
                // Chat's stream finalizer yields only complete SSE events on both paths.
                // Bound how much metadata we can hold for a slow stream, as Sub does.
                retained_bytes >= MAX_PRELUDE || contains_output_or_terminal(bytes)
            }
            Err(_) => true,
        };
        prefix.push(item);
        if ready {
            return;
        }
    }
}

fn contains_output_or_terminal(bytes: &[u8]) -> bool {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let mut len = 0;
        for line in remaining.split_inclusive(|&byte| byte == b'\n') {
            len += line.len();
            if line == b"\n" || line == b"\r\n" {
                break;
            }
        }
        let (event, rest) = remaining.split_at(len);
        remaining = rest;
        let Some(data) = super::chat_stream::event_data(event) else { continue };
        if data.as_ref() == b"[DONE]" {
            return true;
        }
        let Ok(frame) = serde_json::from_slice::<Value>(&data) else { continue };
        if frame.get("error").is_some_and(|error| !error.is_null())
            || crate::server::core::upstream::chat_effective_output(&frame)
            || frame.get("choices").and_then(Value::as_array).is_some_and(|choices| {
                choices.iter().any(|choice| choice.get("finish_reason").and_then(Value::as_str)
                    .is_some_and(|reason| !reason.is_empty()))
            })
        {
            return true;
        }
    }
    false
}

async fn after_placeholder(response: Response) -> stream::BoxStream<'static, Result<Bytes, io::Error>> {
    if is_sse(&response) {
        return response.into_body().into_data_stream().map(|item| item.map_err(io::Error::other)).boxed();
    }
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.ok();
    let error = body.as_deref().and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .and_then(|body| body.get("error").cloned())
        .unwrap_or_else(|| json!({"type": "upstream_error", "code": "gateway_response_error",
            "message": "网关未能建立有效的流式响应"}));
    let frame = crate::server::core::protocol::chat_frame(&json!({"error": error, "status": status.as_u16()}));
    // The error is terminal. A following [DONE] would look like success.
    stream::iter([Ok(frame)]).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn placeholder_precedes_slow_response_and_error_has_no_success_terminal() {
        let response = respond("synthetic".into(), Instant::now(), async {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            Response::builder().status(401).body(Body::from(r#"{"error":{"code":"synthetic_auth"}}"#)).unwrap()
        }).await;
        let mut source = response.into_body().into_data_stream();
        let first = tokio::time::timeout(std::time::Duration::from_millis(20),source.next()).await.unwrap().unwrap().unwrap();
        let data: serde_json::Value = serde_json::from_slice(&first[b"data: ".len()..]).unwrap();
        assert_eq!(data["choices"][0]["delta"]["content"], " ");
        let error = source.next().await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&error).contains("synthetic_auth"));
        assert!(!String::from_utf8_lossy(&error).contains("[DONE]"));
        assert!(source.next().await.is_none());
    }
    #[tokio::test]
    async fn pending_request_is_cancelled_when_downstream_disconnects() {
        struct Guard(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Guard { fn drop(&mut self) { self.0.store(true, std::sync::atomic::Ordering::SeqCst); } }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = dropped.clone();
        let response = respond("synthetic".into(), Instant::now(), async move {
            let _guard = Guard(marker);
            std::future::pending::<Response>().await
        }).await;
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        drop(response);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }
    #[tokio::test]
    async fn early_headers_and_role_only_frame_do_not_cancel_acknowledgement() {
        let (send, answer) = tokio::sync::oneshot::channel();
        let role = ": keepalive\r\n\r\ndata: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n";
        let text = "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking\"}}]}\n\n";
        let response = respond("synthetic".into(), Instant::now() + std::time::Duration::from_millis(10), async move {
            let source = stream::iter([Ok::<_, io::Error>(Bytes::from_static(role.as_bytes()))])
                .chain(stream::once(async move {
                    answer.await.unwrap();
                    Ok(Bytes::from_static(text.as_bytes()))
                }));
            Response::builder().header(header::CONTENT_TYPE,"text/event-stream")
                .body(Body::from_stream(source)).unwrap()
        }).await;
        let mut source = response.into_body().into_data_stream();
        assert!(String::from_utf8_lossy(&source.next().await.unwrap().unwrap()).contains("chatcmpl-gateway-placeholder"));
        send.send(()).unwrap();
        assert_eq!(source.next().await.unwrap().unwrap(), role);
        assert_eq!(source.next().await.unwrap().unwrap(), text);
        assert!(source.next().await.is_none());
    }

    #[tokio::test]
    async fn successful_stream_is_byte_preserved() {
        let bytes = concat!(": waiting\n\n", "data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\ndata: [DONE]\n\n");
        let response = respond("synthetic".into(), Instant::now() + std::time::Duration::from_secs(5), async move {
            Response::builder().header(header::CONTENT_TYPE,"text/event-stream").body(Body::from(bytes)).unwrap()
        }).await;
        let mut source = response.into_body().into_data_stream();
        assert_eq!(source.next().await.unwrap().unwrap(),bytes);
        assert!(source.next().await.is_none());
    }
}
