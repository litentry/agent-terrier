use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "name", rename_all = "snake_case")]
pub enum ProvisionMetric {
    TierUsed {
        service: String,
        tier: u8,
    },
    DurationSeconds {
        service: String,
        seconds: f64,
    },
    TripWireFired {
        service: String,
        kind: String,
        step: String,
    },
    VerificationResult {
        service: String,
        result: VerificationResultLabel,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResultLabel {
    Valid,
    Phantom,
    EndpointDown,
    RateLimited,
}

#[derive(Debug, Clone, Serialize)]
struct LogLine<'a> {
    level: &'static str,
    event: &'static str,
    #[serde(flatten)]
    metric: &'a ProvisionMetric,
}

pub fn emit(metric: &ProvisionMetric) {
    let line = LogLine {
        level: "info",
        event: "provision_metric",
        metric,
    };
    if let Ok(json) = serde_json::to_string(&line) {
        eprintln!("{}", json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_serialization_tagged() {
        let m = ProvisionMetric::TierUsed {
            service: "openrouter".into(),
            tier: 2,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"name\":\"tier_used\""));
        assert!(json.contains("\"service\":\"openrouter\""));
        assert!(json.contains("\"tier\":2"));
    }

    #[test]
    fn verification_result_label_serialization() {
        let labels = [
            VerificationResultLabel::Valid,
            VerificationResultLabel::Phantom,
            VerificationResultLabel::EndpointDown,
            VerificationResultLabel::RateLimited,
        ];
        let jsons: Vec<_> = labels
            .iter()
            .map(|l| serde_json::to_string(l).unwrap())
            .collect();
        let unique: std::collections::HashSet<_> = jsons.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }
}
