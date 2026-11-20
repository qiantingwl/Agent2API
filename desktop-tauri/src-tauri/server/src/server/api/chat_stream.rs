//! Finalize Chat SSE after routing has committed to an upstream. The placeholder
//! stays outside this stream, so it cannot count as upstream output or completion.

use std::{borrow::Cow, collections::HashSet, io, sync::Arc};

use axum::body::Bytes;
use bytes::BytesMut;
use futures::{stream, StreamExt};
use serde::Deserialize;
use serde_json::json;

use crate::server::core::upstream::{
    cancellation::MANUAL_TERMINATED, native::ResponseStream, usage::RequestTelemetry,
};

const MAX_PENDING_EVENT: usize = 8 * 1024 * 1024;
const TRUNCATED: &str = "上游流式传输中断: unexpected EOF before Chat stream completion";

pub(super) fn finalize(source: ResponseStream, telemetry: Arc<RequestTelemetry>) -> ResponseStream {
    Box::new(
        stream::unfold(
            (source, Events::default(), telemetry),
            |(mut source, mut events, telemetry)| async move {
                while !events.ended {
                    match source.next().await {
                        Some(Ok(bytes)) => {
                            if let Some(bytes) = events.push(bytes, &telemetry) {
                                return Some((Ok(bytes), (source, events, telemetry)));
                            }
                            if events.buffer.len() <= MAX_PENDING_EVENT {
                                continue;
                            }
                            return failure(source, events, telemetry, "上游流式事件超过 8 MiB");
                        }
                        Some(Err(error)) => {
                            let message = match error.kind() {
                                _ if error.to_string() == MANUAL_TERMINATED => MANUAL_TERMINATED,
                                io::ErrorKind::TimedOut => "等待上游流式数据超时",
                                _ => TRUNCATED,
                            };
                            return failure(source, events, telemetry, message);
                        }
                        None if events.buffer.is_empty() && events.finished() => break,
                        None => return failure(source, events, telemetry, TRUNCATED),
                    }
                }
                None
            },
        )
        .boxed(),
    )
}

fn failure(
    source: ResponseStream,
    mut events: Events,
    telemetry: Arc<RequestTelemetry>,
    message: &str,
) -> Option<(
    Result<Bytes, io::Error>,
    (ResponseStream, Events, Arc<RequestTelemetry>),
)> {
    events.ended = true;
    events.buffer.clear();
    telemetry.note_error(message);
    let frame = crate::server::core::protocol::chat_frame(&json!({
        "error": {"type": "proxy_error", "message": message}
    }));
    Some((Ok(frame), (source, events, telemetry)))
}

#[derive(Default)]
struct Events {
    buffer: BytesMut,
    scanned: usize,
    line_start: usize,
    ended: bool,
    saw_finish: bool,
    open_choices: HashSet<u64>,
}

#[derive(Deserialize)]
struct Metadata<'a> {
    #[serde(default, borrow)]
    choices: Vec<Choice<'a>>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Choice<'a> {
    #[serde(default)]
    index: u64,
    #[serde(borrow)]
    finish_reason: Option<&'a str>,
}

impl Events {
    fn finished(&self) -> bool {
        // Some compatible upstreams close cleanly after a final choice without [DONE].
        self.saw_finish && self.open_choices.is_empty()
    }

    fn push(&mut self, bytes: Bytes, telemetry: &RequestTelemetry) -> Option<Bytes> {
        if self.buffer.is_empty() {
            let end = self.scan(&bytes, telemetry);
            if !self.ended {
                self.buffer.extend_from_slice(&bytes[end..]);
            }
            return (end != 0).then(|| bytes.slice(..end));
        }
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.extend_from_slice(&bytes);
        let end = self.scan(&buffer, telemetry);
        let complete = buffer.split_to(end).freeze();
        if !self.ended {
            self.buffer = buffer;
        }
        (!complete.is_empty()).then_some(complete)
    }

    fn scan(&mut self, buffer: &[u8], telemetry: &RequestTelemetry) -> usize {
        let mut end = 0;
        for (index, &byte) in buffer.iter().enumerate().skip(self.scanned) {
            if byte != b'\n' {
                continue;
            }
            let line = &buffer[self.line_start..index];
            self.line_start = index + 1;
            if line.is_empty() || line == b"\r" {
                self.inspect(&buffer[end..=index], telemetry);
                end = index + 1;
                if self.ended {
                    break;
                }
            }
        }
        self.scanned = buffer.len() - end;
        self.line_start -= end;
        end
    }

    fn inspect(&mut self, event: &[u8], telemetry: &RequestTelemetry) {
        let Some(payload) = event_data(event) else { return };
        if payload.as_ref() == b"[DONE]" {
            self.ended = true;
            return;
        }
        let Ok(metadata) = serde_json::from_slice::<Metadata<'_>>(&payload) else {
            return;
        };
        if let Some(error) = metadata.error {
            let message = error
                .get("message")
                .and_then(|value| value.as_str())
                .or_else(|| error.as_str())
                .filter(|message| !message.is_empty())
                .unwrap_or("上游返回流式错误");
            telemetry.note_error(message);
            // Legacy sources sometimes emit [DONE] after an error. Stop at the error.
            self.ended = true;
            return;
        }
        for choice in metadata.choices {
            if choice
                .finish_reason
                .is_some_and(|reason| !reason.is_empty())
            {
                self.saw_finish = true;
                self.open_choices.remove(&choice.index);
            } else {
                self.open_choices.insert(choice.index);
            }
        }
    }
}

// Both the placeholder and the stream finalizer consume complete SSE events.
pub(super) fn event_data(event: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut lines = event.split(|&byte| byte == b'\n').filter_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        line.strip_prefix(b"data:").map(|line| line.trim_ascii())
    });
    let first = lines.next()?;
    let Some(second) = lines.next() else { return Some(Cow::Borrowed(first)); };
    let mut payload = first.to_vec();
    for line in std::iter::once(second).chain(lines) {
        payload.push(b'\n');
        payload.extend_from_slice(line);
    }
    Some(Cow::Owned(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(items: Vec<Result<Bytes, io::Error>>) -> (Bytes, Arc<RequestTelemetry>) {
        let telemetry = Arc::new(RequestTelemetry::new());
        let bytes = finalize(Box::new(stream::iter(items)), telemetry.clone())
            .map(|item| item.unwrap())
            .collect::<Vec<_>>()
            .await
            .concat();
        (Bytes::from(bytes), telemetry)
    }

    #[tokio::test]
    async fn preserves_fragmented_content_usage_and_done() {
        let success = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"回答\"}}]}\r\n\r\n",
            "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"completion_tokens\":4}}\n\n",
            "data:[DONE]\r\n\r\n",
        );
        let items = success
            .as_bytes()
            .chunks(1)
            .map(|b| Ok(Bytes::copy_from_slice(b)))
            .collect();
        let (actual, telemetry) = run(items).await;
        assert_eq!(actual, success);
        assert!(telemetry.snapshot().error.is_none());
    }

    #[tokio::test]
    async fn reports_truncation_after_content_without_releasing_partial_event() {
        let content = "data: {\"choices\":[{\"delta\":{\"content\":\"sent\"}}]}\n\n";
        for transport_error in [false, true] {
            let mut items = vec![Ok(Bytes::from(format!("{content}data: {{\"partial\":")))];
            if transport_error {
                items.push(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
            }
            let (actual, telemetry) = run(items).await;
            let error: serde_json::Value =
                serde_json::from_slice(&actual[content.len() + 6..]).unwrap();
            assert_eq!(&actual[..content.len()], content.as_bytes());
            assert_eq!(error["error"]["type"], "proxy_error");
            assert_eq!(error["error"]["message"], TRUNCATED);
            assert_eq!(telemetry.snapshot().error.as_deref(), Some(TRUNCATED));
        }
    }

    #[tokio::test]
    async fn existing_error_wins_over_following_done() {
        let error = "data: {\"error\":{\"type\":\"proxy_error\",\"message\":\"test transport failure\"}}\n\n";
        let (actual, telemetry) =
            run(vec![Ok(Bytes::from(format!("{error}data: [DONE]\n\n")))]).await;
        assert_eq!(actual, error);
        assert_eq!(
            telemetry.snapshot().error.as_deref(),
            Some("test transport failure")
        );
    }

    #[tokio::test]
    async fn accepts_clean_close_after_real_finish_and_preserves_manual_cancel() {
        let finish =
            Bytes::from_static(b"data: {\"choices\":[{\"finish_reason\":\"tool_calls\"}]}\n\n");
        let (actual, telemetry) = run(vec![Ok(finish.clone())]).await;
        assert_eq!(actual, finish);
        assert!(telemetry.snapshot().error.is_none());

        let (actual, telemetry) = run(vec![Err(io::Error::other(MANUAL_TERMINATED))]).await;
        assert!(String::from_utf8_lossy(&actual).contains(MANUAL_TERMINATED));
        assert_eq!(
            telemetry.snapshot().error.as_deref(),
            Some(MANUAL_TERMINATED)
        );
    }
}
