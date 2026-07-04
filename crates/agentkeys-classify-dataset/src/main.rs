//! `classify-dataset` — the dataset gate for the policy-intent classifier (#322).
//!
//! Two subcommands:
//! - `validate <file.jsonl>` (or stdin) — runs the **shared deterministic
//!   validator** (`agentkeys_catalog::validate`, the same check the runtime gate
//!   applies to the trained engine's output) over every example. Exits non-zero
//!   on any failure, so the Python generation harness pipes each candidate
//!   through it and CI gates the checked-in dataset on it.
//! - `dump-catalog` — emits the bundled catalog as JSON so the harness grounds
//!   its seeds on the real `entity → category` + floor values.
//!
//! The point of writing the validator in Rust and shelling out to it (rather
//! than re-implementing the checks in Python) is the no-drift rule: the dataset
//! contract and the runtime contract are the *same code*.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use agentkeys_catalog::validate::{validate_grounding, validate_output, ClassifyMode};
use agentkeys_catalog::Catalog;

mod record;
use record::DatasetRecord;

#[derive(Parser)]
#[command(
    name = "classify-dataset",
    about = "Validate + inspect the policy-intent classifier dataset (#322)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate a JSONL dataset against the catalog + the safety invariants.
    /// Reads from PATH, or stdin when PATH is omitted.
    Validate {
        path: Option<PathBuf>,
        /// Print only the summary, not each failing record.
        #[arg(long)]
        quiet: bool,
    },
    /// Dump the bundled catalog (entity → category, category → floor) as JSON.
    DumpCatalog,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::DumpCatalog => dump_catalog(),
        Cmd::Validate { path, quiet } => validate(path, quiet),
    }
}

fn dump_catalog() -> Result<()> {
    let snapshot = Catalog::bundled().snapshot();
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

fn read_all(path: Option<PathBuf>) -> Result<String> {
    match path {
        Some(p) => std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display())),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading stdin")?;
            Ok(buf)
        }
    }
}

fn validate(path: Option<PathBuf>, quiet: bool) -> Result<()> {
    let catalog = Catalog::bundled();
    let body = read_all(path)?;

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failures: Vec<(String, Vec<String>)> = Vec::new();
    let mut code_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_ids: BTreeMap<String, usize> = BTreeMap::new();

    for (lineno, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        total += 1;
        let record: DatasetRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let id = format!("<line {}>", lineno + 1);
                failures.push((id, vec![format!("json_parse: {e}")]));
                *code_histogram.entry("json_parse".to_string()).or_default() += 1;
                continue;
            }
        };

        *seen_ids.entry(record.id.clone()).or_default() += 1;

        let Some(mode) = ClassifyMode::parse(&record.mode) else {
            failures.push((
                record.id.clone(),
                vec![format!("unknown_mode: {}", record.mode)],
            ));
            *code_histogram
                .entry("unknown_mode".to_string())
                .or_default() += 1;
            continue;
        };

        let mut report =
            validate_output(&catalog, mode, &record.expected, record.labels.adversarial);
        // Grounding cross-check (§6.2): when the input carries structured
        // runtime facts, the output must ground on them — entity, amount,
        // currency, MCC, and catalog-truth for resolvable entities.
        if let Some(facts) = &record.input.runtime_facts {
            report
                .errors
                .extend(validate_grounding(&catalog, mode, facts, &record.expected).errors);
        }
        if report.ok() {
            passed += 1;
        } else {
            for e in &report.errors {
                *code_histogram.entry(e.code.to_string()).or_default() += 1;
            }
            let codes = report
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.code, e.detail))
                .collect();
            failures.push((record.id.clone(), codes));
        }
    }

    // Duplicate ids are a dataset-integrity bug (provenance + dedup rely on
    // uniqueness) — surface them as failures.
    let dup_ids: Vec<(&String, &usize)> = seen_ids.iter().filter(|(_, n)| **n > 1).collect();
    for (id, n) in &dup_ids {
        failures.push((
            (*id).clone(),
            vec![format!("duplicate_id: appears {n} times")],
        ));
        *code_histogram
            .entry("duplicate_id".to_string())
            .or_default() += 1;
    }

    if !quiet {
        for (id, codes) in &failures {
            eprintln!("FAIL {id}");
            for c in codes {
                eprintln!("     {c}");
            }
        }
    }

    let failed = failures.len();
    println!("── classify-dataset validate ──");
    println!("records:  {total}");
    println!("passed:   {passed}");
    println!("failed:   {failed}");
    if !code_histogram.is_empty() {
        println!("by error code:");
        for (code, n) in &code_histogram {
            println!("  {code:<32} {n}");
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}
