"""
Sigma rules integration engine for ThreatClaw SOC Monitor.

Loads Sigma rules from YAML, converts detection logic to Python matching
functions, and evaluates log records against the loaded rule set.

Uses standard library + PyYAML only. No pySigma or sigma-cli dependency.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LogSource:
    """Sigma logsource descriptor."""
    category: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None

    def matches(self, other: "LogSource") -> bool:
        """Return True when *other* satisfies every non-None field of *self*."""
        if self.category is not None and self.category != other.category:
            return False
        if self.product is not None and self.product != other.product:
            return False
        if self.service is not None and self.service != other.service:
            return False
        return True


@dataclass
class SigmaRule:
    """Parsed representation of a single Sigma rule."""
    id: str
    title: str
    status: str
    level: str
    description: str
    author: str
    logsource: LogSource
    detection: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    enabled: bool = True

    # Compiled matcher populated by _compile_detection
    _matcher: Optional[Callable[[dict], dict | None]] = field(
        default=None, repr=False, compare=False,
    )

    def match(self, log_record: dict) -> dict | None:
        """Evaluate *log_record* against this rule.

        Returns a dict of ``{field: matched_value}`` on match, or ``None``.
        """
        if self._matcher is None:
            self._matcher = _compile_detection(self.detection)
        return self._matcher(log_record)


@dataclass
class MatchResult:
    """Outcome of matching a single log record against a rule."""
    rule_id: str
    title: str
    level: str
    matched_fields: dict[str, Any]
    tags: list[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class RuleStats:
    """Aggregate statistics about a loaded rule set."""
    total: int = 0
    by_level: dict[str, int] = field(default_factory=dict)
    by_logsource_category: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# YAML loading helpers
# ---------------------------------------------------------------------------

def _import_yaml():  # pragma: no cover – import indirection
    """Import PyYAML lazily so the rest of the module stays importable."""
    import yaml
    return yaml


def load_rules_from_yaml(yaml_content: str) -> SigmaRule:
    """Parse a single Sigma rule from its YAML text.

    Raises ``ValueError`` when required fields are missing or the document
    cannot be parsed.
    """
    yaml = _import_yaml()

    try:
        doc = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc

    if not isinstance(doc, dict):
        raise ValueError("Sigma rule YAML must be a mapping at the top level")

    # Required fields ---------------------------------------------------
    rule_id = str(doc.get("id", ""))
    title = doc.get("title")
    if not title:
        raise ValueError("Sigma rule is missing required field 'title'")

    detection = doc.get("detection")
    if not detection or not isinstance(detection, dict):
        raise ValueError("Sigma rule is missing or has invalid 'detection' block")

    # Optional / defaulted fields ----------------------------------------
    status = doc.get("status", "experimental")
    level = doc.get("level", "medium")
    description = doc.get("description", "")
    author = doc.get("author", "")
    tags = doc.get("tags", [])
    if not isinstance(tags, list):
        tags = [str(tags)]

    # LogSource -----------------------------------------------------------
    ls_raw = doc.get("logsource", {})
    if not isinstance(ls_raw, dict):
        ls_raw = {}
    logsource = LogSource(
        category=ls_raw.get("category"),
        product=ls_raw.get("product"),
        service=ls_raw.get("service"),
    )

    rule = SigmaRule(
        id=rule_id,
        title=title,
        status=status,
        level=level,
        description=description,
        author=author,
        logsource=logsource,
        detection=detection,
        tags=tags,
    )
    # Pre-compile the matcher so errors surface early.
    rule._matcher = _compile_detection(detection)
    return rule


def load_rules_from_directory(path: str) -> list[SigmaRule]:
    """Recursively load all ``*.yml`` / ``*.yaml`` Sigma rules under *path*.

    Rules that fail to parse are silently skipped (a warning is printed to
    stderr).  Returns the list of successfully loaded rules together with
    aggregated :class:`RuleStats` via the helper :func:`compute_stats`.
    """
    import sys

    rules: list[SigmaRule] = []

    if not os.path.isdir(path):
        raise FileNotFoundError(f"Rules directory not found: {path}")

    for dirpath, _dirnames, filenames in os.walk(path):
        for fname in sorted(filenames):
            if not (fname.endswith(".yml") or fname.endswith(".yaml")):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, encoding="utf-8") as fh:
                    rule = load_rules_from_yaml(fh.read())
                rules.append(rule)
            except Exception as exc:
                print(f"[sigma_engine] skipping {fpath}: {exc}", file=sys.stderr)

    return rules


def compute_stats(rules: list[SigmaRule]) -> RuleStats:
    """Compute aggregate statistics for a list of loaded rules."""
    stats = RuleStats(total=len(rules))
    for r in rules:
        stats.by_level[r.level] = stats.by_level.get(r.level, 0) + 1
        cat = r.logsource.category or "unknown"
        stats.by_logsource_category[cat] = stats.by_logsource_category.get(cat, 0) + 1
    return stats


# ---------------------------------------------------------------------------
# Log matching
# ---------------------------------------------------------------------------

def match_log(
    log_record: dict,
    rules: list[SigmaRule],
    *,
    logsource: LogSource | None = None,
) -> list[MatchResult]:
    """Match *log_record* against every enabled rule in *rules*.

    If *logsource* is given, only rules whose logsource matches will be
    evaluated (efficient pre-filtering by category / product / service).

    Returns a (possibly empty) list of :class:`MatchResult`.
    """
    results: list[MatchResult] = []
    for rule in rules:
        if not rule.enabled:
            continue
        if logsource is not None and not rule.logsource.matches(logsource):
            continue
        matched = rule.match(log_record)
        if matched is not None:
            results.append(MatchResult(
                rule_id=rule.id,
                title=rule.title,
                level=rule.level,
                matched_fields=matched,
                tags=list(rule.tags),
            ))
    return results


# ---------------------------------------------------------------------------
# Detection logic compiler
# ---------------------------------------------------------------------------

# The heart of the module: turn the Sigma ``detection`` dict into a callable
# ``(log_record) -> matched_fields | None``.


def _compile_detection(detection: dict) -> Callable[[dict], dict | None]:
    """Compile the *detection* block into a matcher function.

    Supports:
    * Named selection / filter blocks (dicts or lists-of-dicts)
    * ``condition`` expressions with ``and``, ``or``, ``not``, ``1 of``,
      ``all of``, and parentheses.
    """
    condition_str: str = detection.get("condition", "")
    if not condition_str:
        raise ValueError("detection block has no 'condition'")

    # Build matchers for each named block (everything except "condition").
    block_matchers: dict[str, Callable[[dict], dict | None]] = {}
    for name, spec in detection.items():
        if name == "condition":
            continue
        block_matchers[name] = _compile_block(spec)

    # Parse the condition expression into a tree, then compile it.
    cond_eval = _compile_condition(condition_str, block_matchers)
    return cond_eval


# ---- block compilation (selection / filter) ----


def _compile_block(spec: Any) -> Callable[[dict], dict | None]:
    """Compile a single named block (selection / filter).

    A block is either a dict of ``{field|field|modifier: value(s)}`` or a
    list of such dicts (OR between list elements).
    """
    if isinstance(spec, list):
        # List of dicts – OR between them.
        sub = [_compile_block_dict(s) for s in spec if isinstance(s, dict)]
        if not sub:
            return lambda rec: None

        def _or_matcher(rec: dict) -> dict | None:
            for fn in sub:
                res = fn(rec)
                if res is not None:
                    return res
            return None
        return _or_matcher

    if isinstance(spec, dict):
        return _compile_block_dict(spec)

    # Unsupported format – always false.
    return lambda rec: None


def _compile_block_dict(block: dict) -> Callable[[dict], dict | None]:
    """Compile a single dict block to a matcher.

    All field conditions inside one dict are ANDed together.
    """
    field_matchers: list[tuple[str, Callable[[dict], Any | None]]] = []

    for key, value in block.items():
        parts = key.split("|")
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []
        fm = _compile_field_matcher(field_name, modifiers, value)
        field_matchers.append((field_name, fm))

    def _dict_matcher(rec: dict) -> dict | None:
        matched: dict[str, Any] = {}
        for field_name, fm in field_matchers:
            res = fm(rec)
            if res is None:
                return None
            matched[field_name] = res
        return matched

    return _dict_matcher


def _compile_field_matcher(
    field_name: str,
    modifiers: list[str],
    value: Any,
) -> Callable[[dict], Any | None]:
    """Return a function that checks *field_name* with *modifiers* against *value*."""

    # Normalise value to a list for uniform handling.
    values: list[Any]
    if isinstance(value, list):
        values = value
    else:
        values = [value]

    use_all = "all" in modifiers
    active_modifiers = [m for m in modifiers if m != "all"]

    # Build a single-value checker from modifiers.
    checker = _build_value_checker(active_modifiers)

    def _field_match(rec: dict) -> Any | None:
        rec_val = _get_field(rec, field_name)
        if rec_val is None:
            return None

        rec_str = str(rec_val)
        if use_all:
            # ALL values must match.
            for v in values:
                if not checker(rec_str, v):
                    return None
            return rec_val
        else:
            # ANY value may match (OR).
            for v in values:
                if checker(rec_str, v):
                    return rec_val
            return None

    return _field_match


def _get_field(rec: dict, field_name: str) -> Any | None:
    """Retrieve a field from *rec*, supporting dotted paths."""
    if field_name in rec:
        return rec[field_name]
    # Try dotted path.
    parts = field_name.split(".")
    obj: Any = rec
    for p in parts:
        if isinstance(obj, dict) and p in obj:
            obj = obj[p]
        else:
            return None
    return obj


def _build_value_checker(modifiers: list[str]) -> Callable[[str, Any], bool]:
    """Return a two-arg function ``(record_value_str, rule_value) -> bool``."""
    if "re" in modifiers:
        def _re_check(rec_str: str, pattern: Any) -> bool:
            try:
                return re.search(str(pattern), rec_str) is not None
            except re.error:
                return False
        return _re_check

    if "contains" in modifiers:
        if "startswith" in modifiers:
            # contains AND startswith is unusual – treat as startswith.
            return lambda rs, v: rs.lower().startswith(str(v).lower())
        if "endswith" in modifiers:
            return lambda rs, v: rs.lower().endswith(str(v).lower())
        return lambda rs, v: str(v).lower() in rs.lower()

    if "startswith" in modifiers:
        return lambda rs, v: rs.lower().startswith(str(v).lower())

    if "endswith" in modifiers:
        return lambda rs, v: rs.lower().endswith(str(v).lower())

    # Default: exact match or wildcard match (case-insensitive).
    def _default_check(rec_str: str, rule_val: Any) -> bool:
        rv = str(rule_val)
        if "*" in rv or "?" in rv:
            return fnmatch.fnmatch(rec_str.lower(), rv.lower())
        return rec_str.lower() == rv.lower()
    return _default_check


# ---- condition expression compiler ----

# Minimal recursive-descent parser for Sigma condition strings such as:
#   "selection"
#   "selection and not filter"
#   "1 of selection*"
#   "all of selection*"
#   "(selection1 or selection2) and not filter"


_TOKEN_RE = re.compile(
    r"""
      \(            |
      \)            |
      \b(and|or|not)\b  |
      (1\s+of|all\s+of) |
      ([A-Za-z_][A-Za-z0-9_*]*)
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize(expr: str) -> list[str]:
    tokens: list[str] = []
    for m in _TOKEN_RE.finditer(expr):
        tok = m.group(0).strip()
        # Normalise whitespace inside "1 of" / "all of".
        tok = re.sub(r"\s+", " ", tok)
        tokens.append(tok.lower() if tok.lower() in ("and", "or", "not", "1 of", "all of") else tok)
    return tokens


def _compile_condition(
    condition_str: str,
    block_matchers: dict[str, Callable[[dict], dict | None]],
) -> Callable[[dict], dict | None]:
    """Parse *condition_str* and return a matcher function."""

    tokens = _tokenize(condition_str)
    pos = [0]  # mutable index

    def _peek() -> str | None:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def _advance() -> str:
        tok = tokens[pos[0]]
        pos[0] += 1
        return tok

    def _parse_or() -> Callable[[dict], dict | None]:
        left = _parse_and()
        while _peek() == "or":
            _advance()
            right = _parse_and()
            left = _make_or(left, right)
        return left

    def _parse_and() -> Callable[[dict], dict | None]:
        left = _parse_not()
        while _peek() == "and":
            _advance()
            right = _parse_not()
            left = _make_and(left, right)
        return left

    def _parse_not() -> Callable[[dict], dict | None]:
        if _peek() == "not":
            _advance()
            inner = _parse_atom()
            return _make_not(inner)
        return _parse_atom()

    def _parse_atom() -> Callable[[dict], dict | None]:
        tok = _peek()
        if tok == "(":
            _advance()
            node = _parse_or()
            if _peek() == ")":
                _advance()
            return node
        if tok in ("1 of", "all of"):
            return _parse_of()
        # Named block reference.
        name = _advance()
        if name in block_matchers:
            return block_matchers[name]
        # Wildcard block name (e.g. "selection*").
        if "*" in name:
            matching = [v for k, v in block_matchers.items() if fnmatch.fnmatch(k, name)]
            if not matching:
                return lambda rec: None
            # "selection*" alone without "of" – treat as OR.
            combined = matching[0]
            for m in matching[1:]:
                combined = _make_or(combined, m)
            return combined
        # Unknown block – always false.
        return lambda rec: None

    def _parse_of() -> Callable[[dict], dict | None]:
        quantifier = _advance()  # "1 of" or "all of"
        pattern = _advance() if _peek() is not None else "*"
        matching = [v for k, v in block_matchers.items()
                    if fnmatch.fnmatch(k, pattern) and k != "condition"]
        if not matching:
            return lambda rec: None
        if quantifier == "1 of":
            combined = matching[0]
            for m in matching[1:]:
                combined = _make_or(combined, m)
            return combined
        else:
            combined = matching[0]
            for m in matching[1:]:
                combined = _make_and(combined, m)
            return combined

    result = _parse_or()
    return result


# ---- combinators ----

def _make_and(
    a: Callable[[dict], dict | None],
    b: Callable[[dict], dict | None],
) -> Callable[[dict], dict | None]:
    def _and(rec: dict) -> dict | None:
        ra = a(rec)
        if ra is None:
            return None
        rb = b(rec)
        if rb is None:
            return None
        merged = {}
        merged.update(ra)
        merged.update(rb)
        return merged
    return _and


def _make_or(
    a: Callable[[dict], dict | None],
    b: Callable[[dict], dict | None],
) -> Callable[[dict], dict | None]:
    def _or(rec: dict) -> dict | None:
        ra = a(rec)
        if ra is not None:
            return ra
        return b(rec)
    return _or


def _make_not(
    inner: Callable[[dict], dict | None],
) -> Callable[[dict], dict | None]:
    def _not(rec: dict) -> dict | None:
        ri = inner(rec)
        if ri is None:
            # Inner did NOT match, so "not inner" succeeds.
            return {}
        return None
    return _not
