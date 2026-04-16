use agentkeys_types::TripwireKind;

#[derive(Debug, Clone)]
pub struct TripwireConfig {
    pub selector_timeout_secs: u64,
    pub subprocess_wall_clock_secs: u64,
    pub email_timeout_secs: u64,
}

impl Default for TripwireConfig {
    fn default() -> Self {
        Self {
            selector_timeout_secs: 15,
            subprocess_wall_clock_secs: 120,
            email_timeout_secs: 60,
        }
    }
}

pub fn classify_http_status(status: u16) -> Option<TripwireKind> {
    match status {
        500..=599 => Some(TripwireKind::Http5xx),
        _ => None,
    }
}
