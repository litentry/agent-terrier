use std::sync::Arc;

use crate::audit::AuditLog;
use crate::config::BrokerConfig;
use crate::sts::StsClient;

pub struct AppState {
    pub config: BrokerConfig,
    pub http: reqwest::Client,
    pub audit: AuditLog,
    pub sts: Arc<dyn StsClient>,
}

pub type SharedState = Arc<AppState>;
