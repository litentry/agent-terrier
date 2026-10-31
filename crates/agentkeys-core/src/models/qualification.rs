use std::time::Instant;

use anyhow::{ensure, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use super::{require_local_endpoint, response_json, ModelClient, MAX_MODEL_RESPONSE_BYTES};

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub loopback_endpoint: bool,
    pub chat_model: String,
    pub embedding_model: String,
    pub chat_ms: u128,
    pub stream_ms: u128,
    pub tool_roundtrip_ms: u128,
    pub embedding_ms: u128,
    pub stream_events: usize,
    pub embedding_dimensions: usize,
    pub retrieved_document: usize,
    pub executed_tool_result: i64,
}

fn chat_body(model: &str, messages: Value) -> Value {
    json!({"model":model,"messages":messages,"temperature":0,"max_tokens":256,"reasoning_effort":"none"})
}

fn message(value: &Value) -> Result<&Value> {
    value
        .pointer("/choices/0/message")
        .context("model response has no assistant message")
}

fn content(value: &Value) -> Result<&str> {
    message(value)?["content"].as_str().filter(|text| !text.trim().is_empty()).context("model returned no answer; select a chat-capable model or inspect its token/context limits")
}

pub async fn probe(
    endpoint: &str,
    chat_model: &str,
    embedding_model: &str,
) -> Result<CapabilityReport> {
    probe_authenticated(endpoint, chat_model, embedding_model, None).await
}

pub async fn probe_authenticated(
    endpoint: &str,
    chat_model: &str,
    embedding_model: &str,
    api_key: Option<&str>,
) -> Result<CapabilityReport> {
    require_local_endpoint(endpoint)?;
    ensure!(
        !chat_model.is_empty() && !embedding_model.is_empty(),
        "chat and embedding model names are required"
    );
    let client = ModelClient::new(endpoint, api_key);
    let models = response_json(client.models().await?).await?;
    let available = models["data"]
        .as_array()
        .context("model listing has no data array")?;
    for required in [chat_model, embedding_model] {
        ensure!(available.iter().any(|model| model["id"].as_str() == Some(required)), "required model {required} is not installed; download it explicitly before qualification");
    }
    let started = Instant::now();
    let response = response_json(
        client
            .chat(&chat_body(
                chat_model,
                json!([{"role":"user","content":"Reply with the single word READY."}]),
            ))
            .await?,
    )
    .await?;
    content(&response)?;
    let chat_ms = started.elapsed().as_millis();

    let started = Instant::now();
    let mut request = chat_body(
        chat_model,
        json!([{"role":"user","content":"Count from one to five, using numerals only."}]),
    );
    request["stream"] = json!(true);
    let mut response = client.chat(&request).await?;
    ensure!(
        response.status().is_success(),
        "streaming request failed with HTTP {}",
        response.status().as_u16()
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream")),
        "model did not return an event stream"
    );
    let mut stream = EventStream::default();
    while let Some(chunk) = response.chunk().await? {
        stream.push(&chunk)?;
    }
    stream.finish()?;
    let stream_ms = started.elapsed().as_millis();

    let started = Instant::now();
    let mut messages = json!([{"role":"user","content":"Use the calculate_sum tool to add 17 and 25. Do not calculate it yourself. After the tool returns, report the result."}]);
    let mut request = chat_body(chat_model, messages.clone());
    request["tools"] = json!([{"type":"function","function":{"name":"calculate_sum","description":"Calculate the exact sum of two integers.","parameters":{"type":"object","properties":{"left":{"type":"integer"},"right":{"type":"integer"}},"required":["left","right"],"additionalProperties":false}}}]);
    request["tool_choice"] = json!("auto");
    let response = response_json(client.chat(&request).await?).await?;
    let assistant = message(&response)?;
    let calls = assistant["tool_calls"]
        .as_array()
        .context("model did not request the required tool; select a tool-capable chat model")?;
    ensure!(
        calls.len() == 1 && calls[0]["function"]["name"] == "calculate_sum",
        "model requested an unsupported tool"
    );
    let arguments: Value = serde_json::from_str(
        calls[0]["function"]["arguments"]
            .as_str()
            .context("tool arguments are not JSON text")?,
    )?;
    let left = arguments["left"]
        .as_i64()
        .context("tool left argument is not an integer")?;
    let right = arguments["right"]
        .as_i64()
        .context("tool right argument is not an integer")?;
    ensure!(
        (left == 17 && right == 25) || (left == 25 && right == 17),
        "model selected incorrect tool arguments"
    );
    let executed_tool_result = left
        .checked_add(right)
        .context("tool arithmetic overflow")?;
    let call_id = calls[0]["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .context("tool call has no id")?;
    messages.as_array_mut().unwrap().push(assistant.clone());
    messages.as_array_mut().unwrap().push(
        json!({"role":"tool","tool_call_id":call_id,"content":executed_tool_result.to_string()}),
    );
    let response = response_json(client.chat(&chat_body(chat_model, messages)).await?).await?;
    ensure!(
        content(&response)?.contains(&executed_tool_result.to_string()),
        "model did not use the executed tool result"
    );
    let tool_roundtrip_ms = started.elapsed().as_millis();

    let started = Instant::now();
    let response = response_json(
        client
            .embeddings(&json!({"model":embedding_model,"input":[
                "search_document: The brass telescope is stored in the cedar cabinet.",
                "search_document: A bicycle tire needs air before the morning commute.",
                "search_document: The vegetable soup recipe uses carrots and onions.",
                "search_query: Where is the brass telescope stored?"
            ]}))
            .await?,
    )
    .await?;
    let embeddings = embeddings(&response, 4)?;
    let scores: Vec<f64> = embeddings[..3]
        .iter()
        .map(|vector| cosine(vector, &embeddings[3]))
        .collect::<Result<_>>()?;
    let retrieved_document = scores
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| left.total_cmp(right))
        .context("no recall candidates")?
        .0;
    ensure!(
        retrieved_document == 0,
        "embedding-backed recall did not retrieve the matching document"
    );
    Ok(CapabilityReport {
        loopback_endpoint: true,
        chat_model: chat_model.into(),
        embedding_model: embedding_model.into(),
        chat_ms,
        stream_ms,
        tool_roundtrip_ms,
        embedding_ms: started.elapsed().as_millis(),
        stream_events: stream.events,
        embedding_dimensions: embeddings[0].len(),
        retrieved_document,
        executed_tool_result,
    })
}

pub fn embeddings(response: &Value, count: usize) -> Result<Vec<Vec<f64>>> {
    let rows = response["data"]
        .as_array()
        .context("embedding response has no data array")?;
    ensure!(rows.len() == count, "embedding response count mismatch");
    let mut output = vec![None; count];
    for row in rows {
        let index = row["index"].as_u64().context("embedding index missing")? as usize;
        ensure!(
            index < count && output[index].is_none(),
            "duplicate or invalid embedding index"
        );
        let values = row["embedding"]
            .as_array()
            .context("embedding vector missing")?
            .iter()
            .map(|value| {
                value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .context("invalid embedding value")
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!values.is_empty(), "empty embedding vector");
        output[index] = Some(values);
    }
    let output: Vec<Vec<f64>> = output.into_iter().map(Option::unwrap).collect();
    ensure!(
        output.iter().all(|vector| vector.len() == output[0].len()),
        "embedding dimension mismatch"
    );
    Ok(output)
}

fn cosine(left: &[f64], right: &[f64]) -> Result<f64> {
    let dot: f64 = left
        .iter()
        .zip(right)
        .map(|(left, right)| left * right)
        .sum();
    let norm = |values: &[f64]| values.iter().map(|value| value * value).sum::<f64>().sqrt();
    let denominator = norm(left) * norm(right);
    ensure!(
        denominator > 0.0 && denominator.is_finite() && dot.is_finite(),
        "invalid embedding norm"
    );
    Ok(dot / denominator)
}

#[derive(Default)]
struct EventStream {
    pending: Vec<u8>,
    bytes: usize,
    events: usize,
    content: String,
    done: bool,
}

impl EventStream {
    fn push(&mut self, chunk: &[u8]) -> Result<()> {
        self.bytes += chunk.len();
        ensure!(
            self.bytes <= MAX_MODEL_RESPONSE_BYTES,
            "model stream exceeds size limit"
        );
        self.pending.extend_from_slice(chunk);
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            let line = std::str::from_utf8(&line)?.trim();
            if let Some(event) = line.strip_prefix("data:").map(str::trim) {
                ensure!(!self.done, "model emitted data after stream completion");
                if event == "[DONE]" {
                    self.done = true;
                    continue;
                }
                let event: Value = serde_json::from_str(event)?;
                if let Some(content) = event
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                {
                    self.content.push_str(content);
                }
                self.events += 1;
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.pending.iter().all(u8::is_ascii_whitespace)
                && self.done
                && self.events > 0
                && !self.content.trim().is_empty(),
            "model stream was empty or ended without completion"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_parser_handles_fragmentation_and_rejects_incomplete_data() {
        let bytes = "data: {\"choices\":[{\"delta\":{\"content\":\"你好\"}}]}\n\ndata: [DONE]\n\n"
            .as_bytes();
        let mut stream = EventStream::default();
        for byte in bytes {
            stream.push(&[*byte]).unwrap();
        }
        stream.finish().unwrap();
        assert_eq!(stream.content, "你好");
        assert!(stream.push(b"data: {}\n").is_err());
        let mut incomplete = EventStream::default();
        incomplete.push(b"data: {}").unwrap();
        assert!(incomplete.finish().is_err());
    }

    #[test]
    fn embedding_decoder_reorders_and_rejects_ambiguous_or_invalid_vectors() {
        let valid =
            json!({"data":[{"index":1,"embedding":[0.0,1.0]},{"index":0,"embedding":[1.0,0.0]}]});
        assert_eq!(embeddings(&valid, 2).unwrap()[0], vec![1.0, 0.0]);
        let mut invalid = valid.clone();
        invalid["data"][0]["index"] = json!(0);
        assert!(embeddings(&invalid, 2).is_err());
        invalid = valid.clone();
        invalid["data"][0]["embedding"] = json!([0.0]);
        assert!(embeddings(&invalid, 2).is_err());
        assert!(cosine(&[0.0, 0.0], &[1.0, 0.0]).is_err());
    }
}
