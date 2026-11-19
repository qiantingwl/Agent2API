//! Downstream-only acknowledgement. Never changes upstream telemetry or replay permission.
use std::{future::Future, io};
use axum::{body::{Body, Bytes}, http::header, response::Response};
use futures::{stream, StreamExt};
use serde_json::json;

pub(super) async fn respond(model: String, delay: std::time::Duration,
    response: impl Future<Output = Response> + Send + 'static) -> Response {
    let mut response = Box::pin(response);
    tokio::select! {
        biased;
        ready = &mut response => return ready,
        _ = tokio::time::sleep(delay) => {}
    }
    let placeholder = Bytes::from(format!("data: {}\n\n", json!({
        "id":"chatcmpl-gateway-placeholder", "object":"chat.completion.chunk",
        "created":crate::server::logging::now_ms()/1000, "model":model,
        "choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]
    })));
    let pending = stream::once(async move {
        let response = response.await;
        let status = response.status();
        let sse = response.headers().get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()).is_some_and(|value| value.starts_with("text/event-stream"));
        if status.is_success() && sse {
            return response.into_body().into_data_stream().map(|item| item.map_err(io::Error::other)).boxed();
        }
        let body = axum::body::to_bytes(response.into_body(), 64*1024).await.ok();
        let error = body.as_deref().and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
            .and_then(|body| body.get("error").cloned())
            .unwrap_or_else(|| json!({"type":"upstream_error","code":"gateway_response_error",
                "message":"网关未能建立有效的流式响应"}));
        let frame = Bytes::from(format!("data: {}\n\n", json!({"error":error,"status":status.as_u16()})));
        // Error is terminal. Do not append [DONE], which some clients interpret as success.
        stream::once(async move { Ok::<_,io::Error>(frame) }).boxed()
    }).flatten();
    let source = stream::once(async move { Ok::<_,io::Error>(placeholder) }).chain(pending);
    Response::builder().header(header::CONTENT_TYPE,"text/event-stream")
        .header(header::CACHE_CONTROL,"no-cache").header("X-Accel-Buffering","no")
        .body(Body::from_stream(source)).expect("constant SSE headers")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn placeholder_precedes_slow_response_and_error_has_no_success_terminal() {
        let response = respond("synthetic".into(), std::time::Duration::ZERO, async {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            Response::builder().status(401).body(Body::from(r#"{"error":{"code":"synthetic_auth"}}"#)).unwrap()
        }).await;
        let mut source = response.into_body().into_data_stream();
        let first = tokio::time::timeout(std::time::Duration::from_millis(20),source.next()).await.unwrap().unwrap().unwrap();
        assert!(String::from_utf8_lossy(&first).contains("assistant"));
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
        let response = respond("synthetic".into(), std::time::Duration::ZERO, async move {
            let _guard = Guard(marker);
            std::future::pending::<Response>().await
        }).await;
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        drop(response);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }
    #[tokio::test]
    async fn successful_stream_is_byte_preserved() {
        let bytes = "data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\ndata: [DONE]\n\n";
        let response = respond("synthetic".into(), std::time::Duration::from_secs(5), async move {
            Response::builder().header(header::CONTENT_TYPE,"text/event-stream").body(Body::from(bytes)).unwrap()
        }).await;
        let mut source = response.into_body().into_data_stream();
        assert_eq!(source.next().await.unwrap().unwrap(),bytes);
        assert!(source.next().await.is_none());
    }
}
