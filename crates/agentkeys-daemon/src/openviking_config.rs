//! The OpenViking server's `ov.conf`, rendered by THIS daemon at boot (plan
//! `docs/plan/dsh-plugin-abstraction.md` PR 3): the engine adapter plans it
//! from the pod env (`agentkeys_memory_openviking::server_config` — one typed
//! owner), the daemon writes it 0600 BEFORE the chat loop starts (whose
//! checkpoint restore later touches the marker `start-openviking.sh` waits
//! for), and the start script only execs the server when the file exists.
//! Nothing is rendered on a box with no engine env (a master daemon).

use agentkeys_memory_openviking::server_config::{
    config_file_path, engine_configured, plan_server_config, write_server_config, ServerConfigPlan,
};

/// Render (or clear) the config for this environment. Loud, never fatal:
/// the engine is never load-bearing (chat answers without it).
pub fn render_at_boot() {
    let lookup = |k: &str| std::env::var(k).ok();
    if !engine_configured(lookup) {
        return;
    }
    let path = std::path::PathBuf::from(config_file_path(lookup));
    match plan_server_config(lookup, |p| std::path::Path::new(p).is_file()) {
        ServerConfigPlan::Rendered { config, summary } => match write_server_config(&path, &config)
        {
            Ok(()) => {
                tracing::info!(path = %path.display(), %summary, "openviking: server config rendered")
            }
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "openviking: server config NOT written — the engine will report itself disabled")
            }
        },
        ServerConfigPlan::Disabled { reason } => {
            clear_stale(&path);
            tracing::info!(%reason, "openviking: DISABLED (no server config rendered)");
        }
        ServerConfigPlan::Refused { reason } => {
            clear_stale(&path);
            tracing::error!(%reason, "openviking: REFUSED (no server config rendered)");
        }
    }
}

/// A config from an earlier boot must not start an engine this env disables.
fn clear_stale(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!(path = %path.display(), "openviking: stale server config removed"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "openviking: stale server config could not be removed")
        }
    }
}
