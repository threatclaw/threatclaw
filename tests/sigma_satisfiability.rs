//! SIGMA SATISFIABILITY — the gate the fixture files never provided.
//!
//! The 984 rules of the shipped baseline (`rules/imported/`) were bulk-imported
//! with empty `TODO` fixtures, and the firing harness counts an empty fixture as
//! a pass. So the suite is green while proving nothing about them.
//!
//! The field-resolution oracle (`sigma_pysigma_validate::health_check_field_resolution`)
//! covers one death class: a rule whose fields TC never produces. It cannot see
//! two others:
//!
//!   * **unsatisfiable** — the condition can never be true (bad conversion, a
//!     modifier the engine mis-compiles, contradictory selections). The rule
//!     ships, resolves its fields, and still never fires.
//!   * **over-broad** — the rule fires on ordinary benign telemetry. That one is
//!     worse than a dead rule: it is a false-positive generator we ship.
//!
//! This harness synthesises an event FROM EACH RULE'S OWN LITERALS, runs it
//! through the production engine, and demands:
//!   1. the synthesised event fires the rule (else: unsatisfiable)
//!   2. a benign reference event does NOT (else: over-broad)
//!
//! **What this does not prove.** A positive derived from the rule itself shows
//! the rule is satisfiable — not that it matches what a real attacker's
//! telemetry looks like. That validation needs real attack samples and is a
//! separate job. This is a regression gate on conversion/modifiers/conditions
//! plus an over-breadth detector, and it is honest about being exactly that.
//!
//! Run:
//!   cargo test --test sigma_satisfiability -- --ignored --nocapture
//!   TC_SAT_DIR=/path/to/rules cargo test --test sigma_satisfiability -- --ignored --nocapture

use serde_json::{json, Map, Value};
use threatclaw::agent::sigma_engine::{
    compile_detection_for_tests, match_rule_for_tests, CompiledRule, Condition, FieldMatcher,
};

/// Why a rule could not be judged.
#[derive(Debug, PartialEq)]
enum Unsupported {
    /// `|re` — synthesising a string from an arbitrary PCRE is its own project.
    Regex,
    /// `|cidr` — the range internals are engine-private.
    Cidr,
    /// Keyword-only detection (no field), matched against the whole event body.
    Keywords,
}

// ── event building ────────────────────────────────────────────────────────

/// Set a dotted path (`data.CommandLine`) inside a nested JSON object.
fn set_path(ev: &mut Map<String, Value>, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.len() == 1 {
        ev.insert(parts[0].to_string(), value);
        return;
    }
    let mut cur = ev;
    for p in &parts[..parts.len() - 1] {
        cur = cur
            .entry(p.to_string())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("path segment must be an object");
    }
    cur.insert(parts[parts.len() - 1].to_string(), value);
}

/// Constraints gathered for one field, later collapsed into a single value.
#[derive(Default)]
struct FieldPlan {
    exact: Option<String>,
    prefix: Option<String>,
    suffix: Option<String>,
    contains: Vec<String>,
    numeric: Option<f64>,
    must_exist: bool,
    must_be_absent: bool,
}

impl FieldPlan {
    /// Collapse the constraints into one value. `None` means "leave unset".
    fn render(&self) -> Option<Value> {
        if self.must_be_absent {
            return None;
        }
        if let Some(n) = self.numeric {
            return Some(json!(n.to_string()));
        }
        if let Some(e) = &self.exact {
            return Some(json!(e));
        }
        let mut v = String::new();
        if let Some(p) = &self.prefix {
            v.push_str(p);
        }
        for c in &self.contains {
            // Don't duplicate a fragment the prefix already provides — a rule
            // asking for both would otherwise get "curlcurl…".
            if !v.contains(c.as_str()) {
                v.push_str(c);
            }
        }
        if let Some(s) = &self.suffix {
            if !v.ends_with(s.as_str()) {
                v.push_str(s);
            }
        }
        if v.is_empty() {
            if self.must_exist {
                return Some(json!("x"));
            }
            return None;
        }
        Some(json!(v))
    }
}

/// Expand a glob into a concrete string: `*` → nothing, `?` → one char.
fn expand_wildcard(pattern: &str) -> String {
    let mut out = String::new();
    for c in pattern.chars() {
        match c {
            '*' => {}
            '?' => out.push('x'),
            other => out.push(other),
        }
    }
    out
}

/// Fold one matcher into the per-field plans. Errors on matchers we cannot synthesise.
/// Which branch to take at each OR-group encountered, in traversal order.
/// A single naive choice is not enough: a rule can be satisfiable only through
/// a specific combination (e.g. take the CommandLine branch here BECAUSE another
/// selection already pinned ParentCommandLine to an exact value). Reporting such
/// a rule as "never fires" would be the harness lying, so we search.
struct Choices<'a> {
    picks: &'a [usize],
    cursor: usize,
}

impl Choices<'_> {
    fn next_pick(&mut self, n: usize) -> usize {
        let p = self.picks.get(self.cursor).copied().unwrap_or(0);
        self.cursor += 1;
        if n == 0 { 0 } else { p % n }
    }
}

fn plan_matcher(
    m: &FieldMatcher,
    plans: &mut std::collections::HashMap<String, FieldPlan>,
    ch: &mut Choices,
) -> Result<(), Unsupported> {
    // A keyword selection (`'|all': [truncate, -s]`) compiles to matchers with an
    // EMPTY field name and is evaluated against the whole serialised event. There
    // is no field to set, so a rule needing one cannot be judged here — saying
    // "never fires" would be wrong.
    if matches!(m.audited_field(), Some("")) {
        return Err(Unsupported::Keywords);
    }
    let mut with = |field: &str, f: &mut dyn FnMut(&mut FieldPlan)| {
        let p = plans.entry(field.to_string()).or_default();
        f(p);
    };
    match m {
        FieldMatcher::Exact(f, v) | FieldMatcher::ExactCased(f, v) => {
            with(f, &mut |p| p.exact = Some(v.clone()))
        }
        FieldMatcher::AnyOf(f, vs) => {
            let v = vs.first().cloned().unwrap_or_default();
            with(f, &mut |p| p.exact = Some(v.clone()))
        }
        FieldMatcher::Contains(f, v) | FieldMatcher::ContainsCased(f, v) => {
            with(f, &mut |p| p.contains.push(v.clone()))
        }
        FieldMatcher::ContainsAny(f, vs) => {
            let v = vs.first().cloned().unwrap_or_default();
            with(f, &mut |p| p.contains.push(v.clone()))
        }
        FieldMatcher::ContainsAll(f, vs) => with(f, &mut |p| p.contains.extend(vs.iter().cloned())),
        FieldMatcher::StartsWith(f, v) | FieldMatcher::StartsWithCased(f, v) => {
            with(f, &mut |p| p.prefix = Some(v.clone()))
        }
        FieldMatcher::StartsWithAny(f, vs) | FieldMatcher::StartsWithAll(f, vs) => {
            // `all` with several different prefixes is unsatisfiable by construction;
            // the longest is the only candidate, and the engine check below decides.
            let v = vs.iter().max_by_key(|s| s.len()).cloned().unwrap_or_default();
            with(f, &mut |p| p.prefix = Some(v.clone()))
        }
        FieldMatcher::EndsWith(f, v) | FieldMatcher::EndsWithCased(f, v) => {
            with(f, &mut |p| p.suffix = Some(v.clone()))
        }
        FieldMatcher::EndsWithAny(f, vs) | FieldMatcher::EndsWithAll(f, vs) => {
            let v = vs.iter().max_by_key(|s| s.len()).cloned().unwrap_or_default();
            with(f, &mut |p| p.suffix = Some(v.clone()))
        }
        FieldMatcher::Wildcard(f, pat) => {
            let v = expand_wildcard(pat);
            with(f, &mut |p| p.exact = Some(v.clone()))
        }
        FieldMatcher::Exists(f, want) => {
            let want = *want;
            with(f, &mut |p| {
                if want {
                    p.must_exist = true
                } else {
                    p.must_be_absent = true
                }
            })
        }
        FieldMatcher::NumericLt(f, n) => with(f, &mut |p| p.numeric = Some(n - 1.0)),
        FieldMatcher::NumericLte(f, n) => with(f, &mut |p| p.numeric = Some(*n)),
        FieldMatcher::NumericGt(f, n) => with(f, &mut |p| p.numeric = Some(n + 1.0)),
        FieldMatcher::NumericGte(f, n) => with(f, &mut |p| p.numeric = Some(*n)),
        FieldMatcher::FieldRef(a, b) => {
            with(a, &mut |p| p.exact = Some("sameval".into()));
            with(b, &mut |p| p.exact = Some("sameval".into()));
        }
        FieldMatcher::Regex(_, _) => return Err(Unsupported::Regex),
        FieldMatcher::Cidr(_, _) => return Err(Unsupported::Cidr),
        // OR of groups: satisfying ONE branch is enough. Try them in order and
        // keep the first that we know how to synthesise, so a branch using a
        // regex doesn't disqualify a rule whose other branches are plain.
        FieldMatcher::AnyOfGroups(groups) => {
            let start = ch.next_pick(groups.len());
            let mut last = Unsupported::Keywords;
            // Start at the chosen branch, then wrap: a branch we cannot
            // synthesise (regex) must not disqualify the whole rule.
            for off in 0..groups.len() {
                let g = &groups[(start + off) % groups.len()];
                let mut trial: std::collections::HashMap<String, FieldPlan> = Default::default();
                let mut sub = Choices { picks: ch.picks, cursor: ch.cursor };
                match g.iter().try_for_each(|m| plan_matcher(m, &mut trial, &mut sub)) {
                    Ok(()) => {
                        ch.cursor = sub.cursor;
                        for (k, v) in trial {
                            plans.insert(k, v);
                        }
                        return Ok(());
                    }
                    Err(e) => last = e,
                }
            }
            return Err(last);
        }
    }
    Ok(())
}

/// Collect the selections that must be satisfied for the condition to hold.
/// `Not(x)` contributes nothing: we simply do not feed x's fields, then let the
/// real engine confirm. Returns `None` if the condition references nothing.
fn selections_to_satisfy(cond: &Condition, out: &mut Vec<String>, ch: &mut Choices) {
    match cond {
        Condition::Ref(name) => out.push(name.clone()),
        Condition::And(a, b) => {
            selections_to_satisfy(a, out, ch);
            selections_to_satisfy(b, out, ch);
        }
        // One branch is enough — but WHICH one matters: `1 of selection_*`
        // often folds a branch that compiles to nothing (`errorCode: null`)
        // next to a real one. Always taking the left would report a perfectly
        // satisfiable rule as dead, so the branch is part of the search.
        Condition::Or(a, b) => {
            if ch.next_pick(2) == 0 {
                selections_to_satisfy(a, out, ch)
            } else {
                selections_to_satisfy(b, out, ch)
            }
        }
        Condition::Not(_) => {}
    }
}

/// Build an event that should satisfy the rule, or say why we cannot.
fn synthesise(rule: &CompiledRule, picks: &[usize], filler: bool) -> Result<Value, Unsupported> {
    let mut ch = Choices { picks, cursor: 0 };
    let mut wanted = Vec::new();
    selections_to_satisfy(&rule.condition, &mut wanted, &mut ch);
    let mut plans: std::collections::HashMap<String, FieldPlan> = Default::default();
    let mut saw_field = false;
    for name in &wanted {
        if let Some(ms) = rule.matchers.get(name) {
            for m in ms {
                plan_matcher(m, &mut plans, &mut ch)?;
                saw_field = true;
            }
        }
    }
    // `filler` prepends a token to every non-exact value. Rules commonly exclude
    // themselves with `not <field>|startswith: <x>` while requiring
    // `<field>|contains: <x>` — only a value where the token is NOT at the start
    // satisfies both, which the plain rendering never produces.
    if filler {
        for p in plans.values_mut() {
            if p.exact.is_none() && p.prefix.is_none() && !p.contains.is_empty() {
                p.prefix = Some("z".into());
            }
        }
    }
    if !saw_field {
        // Keyword-only rules match against the serialised event body; there is
        // no field to set, so this harness cannot judge them.
        return Err(Unsupported::Keywords);
    }
    let mut ev = Map::new();
    for (field, plan) in &plans {
        if let Some(v) = plan.render() {
            set_path(&mut ev, field, v);
        }
    }
    Ok(Value::Object(ev))
}

// ── rule loading ──────────────────────────────────────────────────────────

fn tag_for(rule: &CompiledRule) -> String {
    [
        rule.logsource_category.as_deref(),
        rule.logsource_product.as_deref(),
        rule.logsource_service.as_deref(),
    ]
    .iter()
    .flatten()
    .cloned()
    .collect::<Vec<_>>()
    .join(".")
}

fn load_rules(dir: &std::path::Path, out: &mut Vec<CompiledRule>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            load_rules(&p, out);
            continue;
        }
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !(name.ends_with(".yaml") || name.ends_with(".yml")) || name.contains(".test.") {
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&text) else {
            continue;
        };
        let rule_json: Value = serde_json::to_value(&doc).unwrap_or(Value::Null);
        let Some((matchers, condition)) = compile_detection_for_tests(&rule_json["detection"])
        else {
            continue;
        };
        out.push(CompiledRule {
            id: rule_json["id"]
                .as_str()
                .unwrap_or(name)
                .to_string(),
            title: rule_json["title"].as_str().unwrap_or("").to_string(),
            level: rule_json["level"].as_str().unwrap_or("high").to_string(),
            logsource_category: rule_json["logsource"]["category"].as_str().map(String::from),
            logsource_product: rule_json["logsource"]["product"].as_str().map(String::from),
            logsource_service: rule_json["logsource"]["service"].as_str().map(String::from),
            tags: vec![],
            matchers,
            condition,
            disposition: "monitor".into(),
            tier: "queue".into(),
            risk_score: None,
        });
    }
}

/// Replace every leaf value with a neutral token, keeping the shape. The
/// telemetry schema exists for the FIELD oracle, where only the key names
/// matter, so several of its sample values are deliberately attack-flavoured
/// ("Add member to role"). Comparing rules against those would flag precise,
/// correct rules as over-broad. Neutralising the values gives the property we
/// actually want to test: a rule that fires on an event with the right SHAPE
/// but no meaningful CONTENT fires on anything.
fn neutralise(v: &Value) -> Value {
    match v {
        Value::String(_) => json!("benign"),
        Value::Number(_) => json!(1),
        Value::Bool(_) => json!(false),
        Value::Array(a) => Value::Array(a.iter().map(neutralise).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), neutralise(x))).collect()),
        Value::Null => Value::Null,
    }
}

/// Benign reference events, one per tag: the shape TC really produces, with
/// every value neutralised.
fn benign_events() -> Vec<(String, Value)> {
    let path = format!(
        "{}/tests/fixtures/sigma_telemetry_schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("schema"))
        .expect("schema json");
    schema
        .as_object()
        .expect("obj")
        .iter()
        .map(|(tag, fields)| {
            (
                tag.clone(),
                json!({ "eventid": "1", "channel": "synthetic", "data": neutralise(fields) }),
            )
        })
        .collect()
}

/// Runs by default (no `--ignored`): it reads the in-repo baseline, takes under
/// a second, and is the gate that would have caught the OR-compiled-as-AND bug.
#[test]
fn satisfiability_audit() {
    let dir = std::env::var("TC_SAT_DIR")
        .unwrap_or_else(|_| format!("{}/rules/imported", env!("CARGO_MANIFEST_DIR")));
    let mut rules = Vec::new();
    load_rules(std::path::Path::new(&dir), &mut rules);
    assert!(!rules.is_empty(), "no rules loaded from {dir}");

    let benign = benign_events();
    let (mut ok, mut unsat, mut broad) = (0usize, 0usize, 0usize);
    let mut unsupported: std::collections::HashMap<String, usize> = Default::default();
    let mut unsat_ids: Vec<String> = Vec::new();
    let mut broad_ids: Vec<(String, String)> = Vec::new();

    for rule in &rules {
        let tag = tag_for(rule);
        // Bounded search over OR-branch combinations (and the filler variant).
        // Base-4 digits of `n` give the branch pick at each OR-group, so this
        // walks the plausible combinations without exploding: a rule is only
        // called unsatisfiable once none of them fires.
        const ATTEMPTS: usize = 256;
        let mut fired: Option<Value> = None;
        let mut reason: Option<Unsupported> = None;
        'search: for n in 0..ATTEMPTS {
            let picks = [n & 3, (n >> 2) & 3, (n >> 4) & 3, (n >> 6) & 3];
            for filler in [false, true] {
                match synthesise(rule, &picks, filler) {
                    Err(r) => {
                        reason = Some(r);
                        // Unsupported does not depend on the branch pick for
                        // keyword-only rules; keep trying for the OR cases.
                        continue;
                    }
                    Ok(ev) => {
                        if match_rule_for_tests(rule, &ev, Some(&tag)).is_some() {
                            fired = Some(ev);
                            break 'search;
                        }
                    }
                }
            }
        }

        match fired {
            None => {
                if let Some(r) = reason {
                    *unsupported.entry(format!("{r:?}")).or_default() += 1;
                } else {
                    unsat += 1;
                    if unsat_ids.len() < 40 {
                        unsat_ids.push(format!("{} — {}", rule.id, rule.title));
                    }
                }
            }
            Some(_) => {
                ok += 1;
                // Over-breadth: does it also fire on ordinary telemetry?
                for (btag, bev) in &benign {
                    if !btag.contains(&tag) && !tag.contains(btag.as_str()) {
                        continue;
                    }
                    if match_rule_for_tests(rule, bev, Some(btag)).is_some() {
                        broad += 1;
                        if broad_ids.len() < 40 {
                            broad_ids.push((rule.id.clone(), rule.title.clone()));
                        }
                        break;
                    }
                }
            }
        }
    }

    let total = rules.len();
    println!("\n=== SIGMA SATISFIABILITY — {dir} ===");
    println!("  rules compiled     : {total}");
    println!("  provably fireable  : {ok}");
    println!("  NEVER fires        : {unsat}   (condition unsatisfiable / mis-converted)");
    println!("  fires on BENIGN    : {broad}   (over-broad — false-positive generator)");
    let mut un: Vec<_> = unsupported.iter().collect();
    un.sort();
    for (k, v) in un {
        println!("  not judgeable ({k}): {v}");
    }
    if !unsat_ids.is_empty() {
        println!("\n  first rules that can never fire:");
        for r in &unsat_ids {
            println!("    {r}");
        }
    }
    if !broad_ids.is_empty() {
        println!("\n  first over-broad rules:");
        for (id, t) in &broad_ids {
            println!("    {id} — {t}");
        }
    }

    assert_eq!(
        unsat, 0,
        "{unsat} rule(s) can never fire — see the list above. A rule that ships and \
         cannot match anything is a silent false negative."
    );
    assert_eq!(
        broad, 0,
        "{broad} rule(s) fire on benign reference telemetry — see the list above. \
         Shipping those means shipping false positives."
    );
}
