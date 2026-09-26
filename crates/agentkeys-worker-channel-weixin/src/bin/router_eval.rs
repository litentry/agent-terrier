//! Household channels — the router eval: labeled household messages through
//! the contact gate's OWN option rendering, request builder and decision
//! (`jev::channel_options` + `jev::build_request` + `jev::verdict_from`),
//! over channel documents exactly as the gate reads them, against any System
//! One server — Kev, the hosted Jev, or the model gate.
//!
//! Every case without a last channel is also asked with a WRONG last channel
//! (one of the sender's that is not a right answer): a new request must not
//! follow the previous conversation. Exit 1 when anything routes to a wrong
//! channel — or, on a shared channel, to a wrong app — at the chosen
//! thresholds; the grid shows the other thresholds from the same answers.
//!
//! ```text
//! cargo run -p agentkeys-worker-channel-weixin --bin router-eval -- \
//!     --endpoint http://127.0.0.1:8009 --model kev-9b
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use agentkeys_protocol::{
    ChannelApp, ChannelDoc, Contact, ContactRegistry, ContactTier, PresetSummary,
    SystemOneResponse, JEV_PINNED_MODEL,
};
use agentkeys_worker_channel_weixin::jev::{
    self, ChannelOption, JevClient, JevVerdict, RouterConfig,
};
use anyhow::{bail, Context};
use clap::Parser;
use serde::Deserialize;

#[derive(Parser)]
#[command(about = "household channels router eval against a System One server")]
struct Args {
    /// The System One server base (`/v1/systemone` is appended).
    #[arg(long, default_value = "http://127.0.0.1:8009")]
    endpoint: String,
    /// Bearer for the server (Kev behind an SSH tunnel accepts any).
    #[arg(
        long,
        env = "TYPESAFE_API_KEY",
        default_value = "local",
        hide_env_values = true
    )]
    key: String,
    #[arg(long, default_value = JEV_PINNED_MODEL)]
    model: String,
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/eval/router-cases.json"))]
    cases: PathBuf,
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../presets"))]
    presets: PathBuf,
    /// `dev`, `test` or `all`.
    #[arg(long, default_value = "all")]
    split: String,
    #[arg(long, default_value_t = RouterConfig::default().threshold)]
    threshold: f64,
    #[arg(long, default_value_t = RouterConfig::default().continue_threshold)]
    continue_threshold: f64,
}

#[derive(Deserialize)]
struct CaseFile {
    households: BTreeMap<String, Household>,
    #[serde(default)]
    apps: BTreeMap<String, AppText>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Household {
    members: Vec<Member>,
    channels: Vec<ChannelDoc>,
}

#[derive(Deserialize)]
struct Member {
    contact_id: String,
    name: String,
    tier: ContactTier,
}

#[derive(Deserialize, Clone)]
struct AppText {
    description: String,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    split: String,
    household: String,
    sender: String,
    /// The previous turn's channel, `channel/app` when that channel is shared
    /// (a follow-up stays with the app of the previous turn).
    last: Option<String>,
    message: String,
    /// A channel id, `channel/app` on a shared channel, or `unclear`.
    ok: BTreeSet<String>,
}

struct Asked {
    id: String,
    split: String,
    message: String,
    options: Vec<ChannelOption>,
    /// The channels' default apps, by id (what an unaddressed pick goes to).
    defaults: BTreeMap<String, Option<String>>,
    last: Option<String>,
    /// The app of the previous turn, when the case names one.
    last_app: Option<String>,
    ok: BTreeSet<String>,
    counterfactual: bool,
    resp: SystemOneResponse,
}

#[derive(Default)]
struct Score {
    wrong_new: usize,
    wrong_counterfactual: usize,
    covered: usize,
    coverable: usize,
    after_right: usize,
    after: usize,
    malformed: usize,
    wrong: Vec<String>,
    asked_instead: Vec<String>,
}

/// The binding description an app row takes when the case file gives none:
/// the preset's messaging slot reason (as the install seeds it), else the
/// preset's description.
fn preset_description(app: &str, presets: &Path) -> anyhow::Result<String> {
    let path = presets.join(app).join("preset.json");
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "app `{app}` is neither a preset ({}) nor in the case file",
            path.display()
        )
    })?;
    let summary: PresetSummary =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    let (reason_zh, reason) = summary
        .app
        .slots
        .iter()
        .find(|s| s.kind == agentkeys_protocol::ChannelEndpointKind::Messaging)
        .map(|s| (s.reason_zh.clone(), s.reason.clone()))
        .unwrap_or_default();
    Ok(agentkeys_protocol::seed_binding_description(
        &reason_zh,
        &reason,
        &summary.description_zh,
        &summary.description,
        &summary.route_examples,
    ))
}

/// Build the registry the gate would hold for this household.
fn registry_for(
    h: &Household,
    presets: &Path,
    inline: &BTreeMap<String, AppText>,
) -> anyhow::Result<ContactRegistry> {
    let mut reg = ContactRegistry::default();
    for m in &h.members {
        reg.bound.push(Contact {
            contact_id: m.contact_id.clone(),
            transport: "weixin".into(),
            transport_id: m.contact_id.clone(),
            display_name: m.name.clone(),
            tier: m.tier,
            legacy_reach: vec![],
            welcomed: true,
        });
    }
    for doc in &h.channels {
        let mut doc = doc.clone();
        let apps = std::mem::take(&mut doc.apps);
        for app in apps {
            let description = if app.description.trim().is_empty() {
                match inline.get(&app.alias) {
                    Some(t) => t.description.clone(),
                    None => preset_description(&app.alias, presets)?,
                }
            } else {
                app.description.clone()
            };
            doc.upsert_app(ChannelApp { description, ..app });
        }
        reg.channels.push(doc);
    }
    Ok(reg)
}

/// What the verdict amounts to: the channel and the app addressed there.
fn outcome(a: &Asked, verdict: &JevVerdict) -> Option<(String, Option<String>)> {
    match verdict {
        JevVerdict::Route {
            channel,
            addressee: named,
            follow_up,
            ..
        } => {
            let option = a.options.iter().find(|o| &o.id == channel)?;
            let previous = follow_up
                .then(|| a.last_app.clone())
                .flatten()
                .filter(|p| option.apps.iter().any(|x| x.alias.eq_ignore_ascii_case(p)));
            let addressee = if option.apps.len() >= 2 {
                previous
                    .or_else(|| named.clone())
                    .or_else(|| a.defaults.get(channel).cloned().flatten())
            } else {
                option.apps.first().map(|x| x.alias.clone())
            };
            Some((channel.clone(), addressee))
        }
        JevVerdict::Ask { .. } => Some((jev::UNCLEAR_OPTION.to_string(), None)),
        JevVerdict::Malformed(_) => None,
    }
}

/// Whether `(channel, addressee)` is one of the case's right outcomes: an
/// `ok` entry `x` matches the channel alone, `x/app` needs the app too.
fn is_ok(ok: &BTreeSet<String>, channel: &str, addressee: Option<&str>) -> bool {
    ok.iter().any(|o| match o.split_once('/') {
        Some((ch, app)) => ch == channel && addressee == Some(app),
        None => o == channel,
    })
}

fn score(asked: &[Asked], split: &str, threshold: f64, continue_threshold: f64) -> Score {
    let mut s = Score::default();
    for a in asked.iter().filter(|a| a.split == split) {
        let keys = jev::option_keys(&a.options);
        let verdict = jev::verdict_from(
            &a.resp,
            &keys,
            threshold,
            a.last.as_deref(),
            continue_threshold,
        );
        let Some((channel, addressee)) = outcome(a, &verdict) else {
            s.malformed += 1;
            continue;
        };
        let routed = channel != jev::UNCLEAR_OPTION;
        let got = match addressee.as_deref() {
            Some(app) if routed => format!("{channel}/{app}"),
            _ => channel.clone(),
        };
        let right = is_ok(&a.ok, &channel, addressee.as_deref());
        let label = format!(
            "{}{} «{}»{} → {got}",
            a.id,
            if a.counterfactual { "*" } else { "" },
            a.message,
            a.last
                .as_deref()
                .map(|l| format!(" after {l}"))
                .unwrap_or_default()
        );
        if routed && !right {
            if a.counterfactual {
                s.wrong_counterfactual += 1;
            } else {
                s.wrong_new += 1;
            }
            s.wrong.push(label.clone());
        }
        if a.counterfactual {
            continue;
        }
        if a.ok.iter().any(|o| o != jev::UNCLEAR_OPTION) {
            s.coverable += 1;
            if routed && right {
                s.covered += 1;
            } else if !routed && !a.ok.contains(jev::UNCLEAR_OPTION) {
                s.asked_instead.push(label.clone());
            }
        }
        if a.last.is_some() {
            s.after += 1;
            s.after_right += usize::from(right);
        }
    }
    s
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let file: CaseFile = serde_json::from_str(
        &std::fs::read_to_string(&args.cases)
            .with_context(|| format!("read {}", args.cases.display()))?,
    )?;
    let splits: Vec<&str> = match args.split.as_str() {
        "all" => vec!["dev", "test"],
        "dev" => vec!["dev"],
        "test" => vec!["test"],
        other => bail!("--split must be dev, test or all (got `{other}`)"),
    };
    let mut registries: BTreeMap<String, ContactRegistry> = BTreeMap::new();
    for (name, h) in &file.households {
        registries.insert(name.clone(), registry_for(h, &args.presets, &file.apps)?);
    }

    let client = JevClient::new(&args.endpoint, &args.key, 60_000);
    let mut asked = Vec::new();
    let mut latencies_ms = Vec::new();
    let mut server_model = String::new();
    for case in file
        .cases
        .iter()
        .filter(|c| splits.contains(&c.split.as_str()))
    {
        let registry = registries
            .get(&case.household)
            .with_context(|| format!("{}: unknown household `{}`", case.id, case.household))?;
        let sender = registry
            .contact(&case.sender)
            .with_context(|| format!("{}: unknown sender `{}`", case.id, case.sender))?;
        let options = jev::channel_options(registry, &case.sender);
        if options.is_empty() {
            bail!("{}: `{}` speaks on no channel", case.id, case.sender);
        }
        let defaults: BTreeMap<String, Option<String>> = options
            .iter()
            .map(|o| {
                let d = registry
                    .channel(&o.id)
                    .and_then(|doc| doc.default_or_only_app().map(str::to_string));
                (o.id.clone(), d)
            })
            .collect();
        let (last_channel, last_app) = match case.last.as_deref() {
            Some(l) => match l.split_once('/') {
                Some((ch, app)) => (Some(ch.to_string()), Some(app.to_string())),
                None => (Some(l.to_string()), None),
            },
            None => (None, None),
        };
        let mut variants = vec![(last_channel.clone(), false)];
        if case.last.is_none() {
            let right_channels: BTreeSet<String> = case
                .ok
                .iter()
                .map(|o| o.split_once('/').map(|(c, _)| c).unwrap_or(o).to_string())
                .collect();
            if let Some(wrong) = options
                .iter()
                .find(|o| !right_channels.contains(&o.id) && o.operator_of.is_none())
            {
                variants.push((Some(wrong.id.clone()), true));
            }
        }
        for (last, counterfactual) in variants {
            let req = jev::build_request(
                &args.model,
                &case.message,
                &sender.display_name,
                sender.tier.as_str(),
                last.as_deref(),
                &options,
            );
            let started = Instant::now();
            let resp = client
                .decide(&req)
                .await
                .map_err(|e| anyhow::anyhow!("{}: {e}", case.id))?;
            latencies_ms.push(started.elapsed().as_millis());
            server_model.clone_from(&resp.model);
            asked.push(Asked {
                id: case.id.clone(),
                split: case.split.clone(),
                message: case.message.clone(),
                options: options.clone(),
                defaults: defaults.clone(),
                last_app: if counterfactual {
                    None
                } else {
                    last_app.clone()
                },
                last,
                ok: case.ok.clone(),
                counterfactual,
                resp,
            });
        }
    }

    latencies_ms.sort_unstable();
    println!(
        "router eval · {} · model `{}` · {} requests · round trip median {} ms, max {} ms",
        args.endpoint,
        server_model,
        asked.len(),
        latencies_ms
            .get(latencies_ms.len() / 2)
            .copied()
            .unwrap_or(0),
        latencies_ms.last().copied().unwrap_or(0),
    );
    let mut any_wrong = false;
    for split in &splits {
        let s = score(&asked, split, args.threshold, args.continue_threshold);
        any_wrong |= !s.wrong.is_empty();
        println!(
            "\n[{split}] threshold {} · follow-up {}: wrong routes {} (new requests {}, after a wrong last channel {}) · routed right {}/{} ({:.0}%) · right after a previous channel {}/{} · malformed {}",
            args.threshold,
            args.continue_threshold,
            s.wrong.len(),
            s.wrong_new,
            s.wrong_counterfactual,
            s.covered,
            s.coverable,
            100.0 * s.covered as f64 / s.coverable.max(1) as f64,
            s.after_right,
            s.after,
            s.malformed,
        );
        for w in &s.wrong {
            println!("  WRONG  {w}");
        }
        for m in &s.asked_instead {
            println!("  asked  {m}");
        }
        println!("  grid (wrong routes / routed right):");
        for t in [0.4, 0.45, 0.5, 0.55, 0.6] {
            let cells: Vec<String> = [0.6, 0.7, 0.8, 0.9]
                .iter()
                .map(|&hi| {
                    let g = score(&asked, split, t, hi);
                    format!(
                        "follow-up {hi}: {:>2} / {:>3.0}%",
                        g.wrong.len(),
                        100.0 * g.covered as f64 / g.coverable.max(1) as f64
                    )
                })
                .collect();
            println!("    threshold {t:<4}  {}", cells.join("   "));
        }
    }
    if any_wrong {
        std::process::exit(1);
    }
    Ok(())
}
