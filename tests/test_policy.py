import pytest
from app.policy import load_pipeline


def write(tmp_path, text):
    p = tmp_path / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_only_enabled_guards_are_loaded(tmp_path):
    p = write(tmp_path, """
input:
  - guard: pii_regex
    enabled: true
  - guard: injection_rules
    enabled: false
""")
    pipe = load_pipeline(p)
    assert [g.name for g in pipe.guards] == ["pii_regex"]


def test_threshold_from_yaml_is_applied(tmp_path):
    p = write(tmp_path, """
input:
  - guard: injection_rules
    threshold: 0.95
""")
    pipe = load_pipeline(p)
    assert pipe.guards[0].threshold == 0.95


def test_unknown_guard_raises(tmp_path):
    p = write(tmp_path, """
input:
  - guard: does_not_exist
""")
    with pytest.raises(ValueError):
        load_pipeline(p)