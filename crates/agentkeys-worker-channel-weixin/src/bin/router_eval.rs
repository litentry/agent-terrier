//! Household channels — the router eval: labeled household messages through
//! the contact gate's OWN option rendering, request builder and decision
//! (`jev::channel_options` + `jev::build_request` + `jev::verdict_from`),
//! over channel documents exactly as the gate reads them, against one or more
//! decision models — Kev, the hosted Jev, or both through the model gate.
//!
//! Every case without a last channel is also asked with a WRONG last channel
//! (one of the sender's that is not a right answer): a new request must not
//! follow the previous conversation. Exit 1 when anything routes to a wrong
//! channel — or, on a shared channel, to a wrong app — at the chosen
//! thresholds; the grid shows the other thresholds from the same answers.
//!
//! Two or more `--model`s compare them on the same requests, asked one after
//! the other for each case (so both see the same network minute): wrong
//! routes, routed right, round trip, tokens, and every case they disagree on.
//!
//! An explicit --endpoint receives every selected model. No host credential discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agentkeys_protocol::{
    ChannelApp, ChannelDoc, Contact, ContactRegistry, ContactTier, PresetSummary, SystemOneRequest,
    SystemOneResponse, JEV_PINNED_MODEL,
};
use agentkeys_worker_channel_weixin::jev::{
    self, ChannelOption, JevClient, JevError, JevVerdict, RouterConfig,
};
use anyhow::{bail, Context};
use clap::Parser;
use serde::Deserialize;

#[derive(Parser)]
#[command(about = "household channels router eval against one or more System One models")]
struct Args {
    /// One System One server for every model (`/v1/systemone` is appended):
    /// a local decision service or the model gate. Required explicitly.
    #[arg(long)]
    endpoint: Option<String>,
    /// Optional explicit bearer for the selected endpoint.
    #[arg(
        long,
        env = "ROUTER_EVAL_ENDPOINT_KEY",
        default_value = "",
        hide_env_values = true
    )]
    key: String,
    /// The model to ask; repeat it (or comma-separate) to compare models.
    #[arg(long = "model", value_delimiter = ',', default_value = JEV_PINNED_MODEL)]
    models: Vec<String>,
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

/// One request the eval asks every model: a case, with its real or wrong
/// previous channel.
struct Question {
    id: String,
    split: String,
    message: String,
    sender: String,
    sender_tier: String,
    options: Vec<ChannelOption>,
    /// The channels' default apps, by id (what an unaddressed pick goes to).
    defaults: BTreeMap<String, Option<String>>,
    last: Option<String>,
    /// The app of the previous turn, when the case names one.
    last_app: Option<String>,
    ok: BTreeSet<String>,
    counterfactual: bool,
}

struct Asked<'a> {
    q: &'a Question,
    resp: SystemOneResponse,
}

/// One model's run over every question.
struct Run<'a> {
    model: String,
    server: String,
    client: JevClient,
    answered_by: String,
    asked: Vec<Asked<'a>>,
    latencies_ms: Vec<u128>,
    input_tokens: u64,
    output_tokens: u64,
    retries: u32,
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

/// Every request the eval asks, in case order.
fn questions_for(file: &CaseFile, args: &Args, splits: &[&str]) -> anyhow::Result<Vec<Question>> {
    let mut registries: BTreeMap<String, ContactRegistry> = BTreeMap::new();
    for (name, h) in &file.households {
        registries.insert(name.clone(), registry_for(h, &args.presets, &file.apps)?);
    }
    let mut out = Vec::new();
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
            out.push(Question {
                id: case.id.clone(),
                split: case.split.clone(),
                message: case.message.clone(),
                sender: sender.display_name.clone(),
                sender_tier: sender.tier.as_str().to_string(),
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
            });
        }
    }
    Ok(out)
}

/// TypeSafe asks callers to retry a 429 or 529 with exponential backoff
/// (<https://docs.typesafe.ai/api.md>); a dropped connection or a gateway 5xx
/// is retried the same way. Returns the answer, the successful attempt's
/// round trip, and how many retries it took.
async fn decide_with_retry(
    client: &JevClient,
    req: &SystemOneRequest,
) -> Result<(SystemOneResponse, u128, u32), JevError> {
    const MAX_RETRIES: u32 = 4;
    let mut retries = 0;
    loop {
        let started = Instant::now();
        match client.decide(req).await {
            Ok(resp) => return Ok((resp, started.elapsed().as_millis(), retries)),
            Err(e)
                if retries < MAX_RETRIES
                    && matches!(
                        e,
                        JevError::Transport(_) | JevError::Status(429 | 500 | 502 | 504 | 529, _)
                    ) =>
            {
                retries += 1;
                tokio::time::sleep(Duration::from_millis(1000 << (retries - 1))).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// What a model's answer amounts to: the channel and the app addressed there,
/// `unclear` for an ask, `None` for an unusable answer.
fn outcome(a: &Asked, threshold: f64, continue_threshold: f64) -> Option<(String, Option<String>)> {
    let keys = jev::option_keys(&a.q.options);
    let verdict = jev::verdict_from(
        &a.resp,
        &keys,
        threshold,
        a.q.last.as_deref(),
        continue_threshold,
    );
    match verdict {
        JevVerdict::Route {
            channel,
            addressee: named,
            follow_up,
            ..
        } => {
            let option = a.q.options.iter().find(|o| o.id == channel)?;
            let previous = follow_up
                .then(|| a.q.last_app.clone())
                .flatten()
                .filter(|p| option.apps.iter().any(|x| x.alias.eq_ignore_ascii_case(p)));
            let addressee = if option.apps.len() >= 2 {
                previous
                    .or_else(|| named.clone())
                    .or_else(|| a.q.defaults.get(&channel).cloned().flatten())
            } else {
                option.apps.first().map(|x| x.alias.clone())
            };
            Some((channel, addressee))
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

/// The outcome as one word: `channel`, `channel/app`, `unclear` (asked) or
/// `malformed`.
fn outcome_label(o: &Option<(String, Option<String>)>) -> String {
    match o {
        None => "malformed".into(),
        Some((channel, Some(app))) if channel != jev::UNCLEAR_OPTION => format!("{channel}/{app}"),
        Some((channel, _)) => channel.clone(),
    }
}

fn question_label(q: &Question) -> String {
    format!(
        "{}{} «{}»{}",
        q.id,
        if q.counterfactual { "*" } else { "" },
        q.message,
        q.last
            .as_deref()
            .map(|l| format!(" after {l}"))
            .unwrap_or_default()
    )
}

fn score(asked: &[Asked], split: &str, threshold: f64, continue_threshold: f64) -> Score {
    let mut s = Score::default();
    for a in asked.iter().filter(|a| a.q.split == split) {
        let Some((channel, addressee)) = outcome(a, threshold, continue_threshold) else {
            s.malformed += 1;
            continue;
        };
        let routed = channel != jev::UNCLEAR_OPTION;
        let got = outcome_label(&Some((channel.clone(), addressee.clone())));
        let right = is_ok(&a.q.ok, &channel, addressee.as_deref());
        let label = format!("{} → {got}", question_label(a.q));
        if routed && !right {
            if a.q.counterfactual {
                s.wrong_counterfactual += 1;
            } else {
                s.wrong_new += 1;
            }
            s.wrong.push(label.clone());
        }
        if a.q.counterfactual {
            continue;
        }
        if a.q.ok.iter().any(|o| o != jev::UNCLEAR_OPTION) {
            s.coverable += 1;
            if routed && right {
                s.covered += 1;
            } else if !routed && !a.q.ok.contains(jev::UNCLEAR_OPTION) {
                s.asked_instead.push(label.clone());
            }
        }
        if a.q.last.is_some() {
            s.after += 1;
            s.after_right += usize::from(right);
        }
    }
    s
}

fn percent(n: usize, d: usize) -> f64 {
    100.0 * n as f64 / d.max(1) as f64
}

fn quantile(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

/// One model's report: the round trips, then per split the wrong routes, the
/// right routes, and the threshold grid. Returns whether anything routed wrong.
fn print_run(run: &Run, splits: &[&str], args: &Args) -> bool {
    let mut sorted = run.latencies_ms.clone();
    sorted.sort_unstable();
    println!(
        "router eval · {} · model `{}` · {} requests · round trip median {} ms, max {} ms{}",
        run.server,
        run.answered_by,
        run.asked.len(),
        quantile(&sorted, 0.5),
        sorted.last().copied().unwrap_or(0),
        if run.retries > 0 {
            format!(" · {} retried", run.retries)
        } else {
            String::new()
        }
    );
    let mut any_wrong = false;
    for split in splits {
        let s = score(&run.asked, split, args.threshold, args.continue_threshold);
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
            percent(s.covered, s.coverable),
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
                    let g = score(&run.asked, split, t, hi);
                    format!(
                        "follow-up {hi}: {:>2} / {:>3.0}%",
                        g.wrong.len(),
                        percent(g.covered, g.coverable)
                    )
                })
                .collect();
            println!("    threshold {t:<4}  {}", cells.join("   "));
        }
    }
    any_wrong
}

/// The models side by side on the same requests: per split the headline
/// numbers, how often they reached the same outcome, and every case they
/// did not.
fn print_comparison(runs: &[Run], splits: &[&str], args: &Args) {
    const LABEL: usize = 34;
    let width = runs
        .iter()
        .map(|r| r.model.chars().count())
        .max()
        .unwrap_or(0)
        .max(16)
        + 2;
    let row = |label: &str, cells: Vec<String>| {
        let cells: Vec<String> = cells.iter().map(|c| format!("{c:>width$}")).collect();
        println!("  {label:<LABEL$}{}", cells.join(""));
    };
    println!(
        "\n══ comparison · threshold {} · follow-up {} ══",
        args.threshold, args.continue_threshold
    );
    row("", runs.iter().map(|r| r.model.clone()).collect());
    row(
        "answered by",
        runs.iter().map(|r| r.answered_by.clone()).collect(),
    );
    let sorted: Vec<Vec<u128>> = runs
        .iter()
        .map(|r| {
            let mut v = r.latencies_ms.clone();
            v.sort_unstable();
            v
        })
        .collect();
    row(
        "round trip median / p90 (ms)",
        sorted
            .iter()
            .map(|v| format!("{} / {}", quantile(v, 0.5), quantile(v, 0.9)))
            .collect(),
    );
    row(
        "tokens per request (in / out)",
        runs.iter()
            .map(|r| {
                let n = r.asked.len().max(1) as u64;
                format!("{} / {}", r.input_tokens / n, r.output_tokens / n)
            })
            .collect(),
    );
    for split in splits {
        let scores: Vec<Score> = runs
            .iter()
            .map(|r| score(&r.asked, split, args.threshold, args.continue_threshold))
            .collect();
        println!("\n  [{split}]");
        row(
            "wrong routes",
            scores.iter().map(|s| s.wrong.len().to_string()).collect(),
        );
        row(
            "  on a new request / wrong last",
            scores
                .iter()
                .map(|s| format!("{} / {}", s.wrong_new, s.wrong_counterfactual))
                .collect(),
        );
        row(
            "routed right",
            scores
                .iter()
                .map(|s| {
                    format!(
                        "{}/{} ({:.0}%)",
                        s.covered,
                        s.coverable,
                        percent(s.covered, s.coverable)
                    )
                })
                .collect(),
        );
        row(
            "asked where an answer was right",
            scores
                .iter()
                .map(|s| s.asked_instead.len().to_string())
                .collect(),
        );
        row(
            "right after a previous channel",
            scores
                .iter()
                .map(|s| format!("{}/{}", s.after_right, s.after))
                .collect(),
        );
        row(
            "malformed",
            scores.iter().map(|s| s.malformed.to_string()).collect(),
        );
        // The same request, every model's outcome.
        let n = runs[0].asked.len();
        let (mut same, mut total) = (0usize, 0usize);
        let mut differ: Vec<String> = Vec::new();
        for i in (0..n).filter(|i| runs[0].asked[*i].q.split == *split) {
            let outcomes: Vec<Option<(String, Option<String>)>> = runs
                .iter()
                .map(|r| outcome(&r.asked[i], args.threshold, args.continue_threshold))
                .collect();
            total += 1;
            if outcomes.windows(2).all(|w| w[0] == w[1]) {
                same += 1;
                continue;
            }
            let q = runs[0].asked[i].q;
            let cells: Vec<String> = runs
                .iter()
                .zip(&outcomes)
                .map(|(r, o)| {
                    let mark = match o {
                        Some((ch, app)) if ch != jev::UNCLEAR_OPTION => {
                            if is_ok(&q.ok, ch, app.as_deref()) {
                                " ✓"
                            } else {
                                " ✗"
                            }
                        }
                        _ => "",
                    };
                    format!("{}: {}{mark}", r.model, outcome_label(o))
                })
                .collect();
            differ.push(format!("{} → {}", question_label(q), cells.join(" · ")));
        }
        println!(
            "  same outcome on {same}/{total} requests ({:.0}%)",
            percent(same, total)
        );
        for d in &differ {
            println!("    differ  {d}");
        }
    }
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
    let mut models: Vec<String> = Vec::new();
    for m in args
        .models
        .iter()
        .map(|m| m.trim())
        .filter(|m| !m.is_empty())
    {
        if !models.iter().any(|x| x == m) {
            models.push(m.to_string());
        }
    }
    if models.is_empty() {
        bail!("--model needs at least one model id");
    }
    let questions = questions_for(&file, &args, &splits)?;

    let server = args
        .endpoint
        .as_ref()
        .context("--endpoint is required; no provider discovery")?;
    agentkeys_core::models::base_url(server)?;
    let mut runs: Vec<Run> = Vec::new();
    for model in &models {
        let key = &args.key;
        runs.push(Run {
            model: model.clone(),
            client: JevClient::new(server, key, 60_000),
            server: server.clone(),
            answered_by: String::new(),
            asked: Vec::new(),
            latencies_ms: Vec::new(),
            input_tokens: 0,
            output_tokens: 0,
            retries: 0,
        });
    }
    for q in &questions {
        for run in runs.iter_mut() {
            let req = jev::build_request(
                &run.model,
                &q.message,
                &q.sender,
                &q.sender_tier,
                q.last.as_deref(),
                &q.options,
            );
            let (resp, took_ms, retries) = decide_with_retry(&run.client, &req)
                .await
                .map_err(|e| anyhow::anyhow!("{} · {}: {e}", run.model, q.id))?;
            run.latencies_ms.push(took_ms);
            run.retries += retries;
            run.input_tokens += resp.usage.input_tokens;
            run.output_tokens += resp.usage.output_tokens;
            run.answered_by.clone_from(&resp.model);
            run.asked.push(Asked { q, resp });
        }
    }

    let mut any_wrong = false;
    for (i, run) in runs.iter().enumerate() {
        if i > 0 {
            println!("\n────────────────────────────────────────────────────────────");
        }
        any_wrong |= print_run(run, &splits, &args);
    }
    if runs.len() > 1 {
        print_comparison(&runs, &splits, &args);
    }
    if any_wrong {
        std::process::exit(1);
    }
    Ok(())
}
