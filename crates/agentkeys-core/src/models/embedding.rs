use anyhow::{ensure, Context, Result};
use serde_json::Value;

pub fn decode(response: &Value, count: usize) -> Result<Vec<Vec<f64>>> {
    ensure!(count > 0, "embedding count must be positive");
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

pub fn cosine(left: &[f64], right: &[f64]) -> Result<f64> {
    ensure!(
        !left.is_empty() && left.len() == right.len(),
        "embedding dimension mismatch"
    );
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
