"""Assertion-based tests for the MITRE ATT&CK + ATLAS MCP server.

Run with:  pytest            (preferred)
       or:  python test_mcp_tools.py   (fallback: runs the same checks)

The tests exercise the private `_helper` functions in ``main`` and the
``AttackDataWrapper``. They validate structure and the behaviour added in
v0.2 (deprecated/revoked filtering, correct search totals with offset
paging, platform filtering, case-insensitive group aliases, and
fail-loud data loading).
"""

import os

import pytest

import main
from attack_data_wrapper import AttackDataWrapper, load_attack_data


# --------------------------- helpers ---------------------------

def _assert_summary_list(result):
    """A summary-list result must have list items and an integer total."""
    assert isinstance(result, dict)
    assert isinstance(result["items"], list)
    assert isinstance(result["total"], int)
    assert result["total"] >= len(result["items"])


# --------------------------- ATT&CK list endpoints ---------------------------

@pytest.mark.parametrize("getter", [
    main._get_techniques,
    main._get_tactics,
    main._get_groups,
    main._get_software,
    main._get_mitigations,
])
def test_attack_summary_lists(getter):
    result = getter(limit=3, offset=0)
    _assert_summary_list(result)
    assert 0 < len(result["items"]) <= 3
    first = result["items"][0]
    assert "id" in first and "name" in first


def test_pagination_offset_returns_distinct_pages():
    page1 = main._get_techniques(limit=5, offset=0)
    page2 = main._get_techniques(limit=5, offset=5)
    assert page1["total"] == page2["total"]
    ids1 = {i["id"] for i in page1["items"]}
    ids2 = {i["id"] for i in page2["items"]}
    assert ids1.isdisjoint(ids2)


# --------------------------- deprecated / revoked filtering ---------------------------

def test_deprecated_excluded_by_default():
    active = main._get_techniques(limit=1)["total"]
    with_inactive = main._get_techniques(limit=1, include_deprecated=True)["total"]
    assert with_inactive > active, "including deprecated should return more objects"


def test_wrapper_active_filter():
    w = main.attack_data
    active = w.get_techniques()
    all_objs = w.get_techniques(include_inactive=True)
    assert len(active) < len(all_objs)
    assert all(not t.get("revoked") and not t.get("x_mitre_deprecated") for t in active)


# --------------------------- platform filter ---------------------------

def test_platform_filter_subset():
    total = main._get_techniques(limit=2000)["total"]
    windows = main._get_techniques(limit=2000, platform="Windows")["total"]
    assert 0 < windows < total
    # Case-insensitive
    windows_lower = main._get_techniques(limit=2000, platform="windows")["total"]
    assert windows_lower == windows


def test_platform_filter_by_tactic():
    total = main._get_techniques_by_tactic("TA0002", limit=2000)["total"]
    windows = main._get_techniques_by_tactic("TA0002", limit=2000, platform="Windows")["total"]
    assert 0 < windows <= total


# --------------------------- by-ID endpoints ---------------------------

def test_technique_by_id():
    t = main._get_technique_by_id("T1055")
    assert t["name"] == "Process Injection"
    assert t["id"].startswith("attack-pattern--")
    assert t["mitre_link"].endswith("/T1055")


def test_technique_by_id_is_case_insensitive():
    assert main._get_technique_by_id("t1055")["name"] == "Process Injection"


def test_technique_by_id_not_found():
    assert main._get_technique_by_id("T9999999") == {}


def test_tactic_by_id():
    t = main._get_tactic_by_id("TA0001")
    assert t["x_mitre_shortname"] == "initial-access"


def test_mitigation_by_id():
    m = main._get_mitigation_by_id("M1036")
    assert m["id"].startswith("course-of-action--")
    assert m["name"]


def test_group_by_alias_case_insensitive():
    canonical = main._get_group_by_alias("APT29")
    assert canonical["name"] == "APT29"
    # Different case and a secondary alias resolve to the same group.
    assert main._get_group_by_alias("apt29")["id"] == canonical["id"]
    assert main._get_group_by_alias("midnight blizzard")["id"] == canonical["id"]


# --------------------------- relationships ---------------------------

def test_mitigations_for_technique():
    result = main._get_mitigations_for_technique("T1055")
    _assert_summary_list(result)
    assert result["total"] >= 1


def test_techniques_used_by_group():
    result = main._get_techniques_used_by_group("APT29")
    _assert_summary_list(result)
    assert result["total"] >= 1


def test_software_used_by_group():
    result = main._get_software_used_by_group("APT29")
    _assert_summary_list(result)


# --------------------------- search ---------------------------

def test_search_total_reflects_all_matches():
    """total must count every match, not just the returned page."""
    result = main._search_by_name("access", object_type="techniques", limit=3)
    assert result["total"] >= len(result["items"])
    assert len(result["items"]) == 3
    # A second page continues from the same result set.
    page2 = main._search_by_name("access", object_type="techniques", limit=3, offset=3)
    ids1 = {i["id"] for i in result["items"]}
    ids2 = {i["id"] for i in page2["items"]}
    assert ids1.isdisjoint(ids2)


def test_search_unknown_object_type():
    result = main._search_by_name("x", object_type="bogus")
    assert "error" in result


# --------------------------- ATLAS ---------------------------

@pytest.mark.parametrize("getter", [
    main._get_atlas_techniques,
    main._get_atlas_tactics,
    main._get_atlas_mitigations,
])
def test_atlas_summary_lists(getter):
    result = getter(limit=3, offset=0)
    _assert_summary_list(result)
    assert len(result["items"]) > 0


def test_atlas_technique_by_id():
    t = main._get_atlas_technique_by_id("AML.T0000")
    assert t.get("id", "").upper() == "AML.T0000"


def test_atlas_search_total_and_offset():
    result = main._search_atlas_by_name("model", limit=2)
    assert result["total"] >= len(result["items"])
    if result["total"] > 2:
        page2 = main._search_atlas_by_name("model", limit=2, offset=2)
        assert page2["items"] and page2["items"][0]["id"] != result["items"][0]["id"]


def test_atlas_to_attack_mapping():
    result = main._get_atlas_to_attack_mapping("AML.T0000")
    assert result["item_type"] == "technique"
    assert "atlas_item" in result


# --------------------------- wrapper: fail loud ---------------------------

def test_wrapper_raises_on_missing_file():
    with pytest.raises(RuntimeError):
        load_attack_data("does-not-exist-12345.json")


def test_wrapper_raises_on_empty_objects(tmp_path):
    bad = tmp_path / "empty.json"
    bad.write_text('{"type": "bundle", "objects": []}')
    with pytest.raises(RuntimeError):
        AttackDataWrapper(str(bad))


# --------------------------- MORIARTY (default-off) ---------------------------

import re


def test_moriarty_disarmed_by_default():
    """With MORIARTY_MODE unset, the module loads in the disarmed state."""
    assert main.MORIARTY_MODE is False


def test_moriarty_truthiness_parsing():
    """Only on/1/true/yes (any case) arm the framework."""
    for truthy in ("on", "1", "true", "yes", "ON", "Yes", " True "):
        assert main._is_truthy(truthy) is True
    for falsey in (None, "", "off", "0", "false", "no", "maybe"):
        assert main._is_truthy(falsey) is False


def test_moriarty_helpers_importable_when_disarmed():
    """Private helpers work even when tools are not registered."""
    techs = main._get_moriarty_techniques(limit=20)
    assert techs["total"] == 10
    assert main._get_moriarty_tactics()["total"] == 3
    assert main._get_moriarty_mitigations()["total"] == 1
    obj = main._get_moriarty_technique_by_id("MOR.T0001")
    assert obj.get("id") == "MOR.T0001"
    assert obj.get("name") == "The Baker Street Chalk-Mark"


def test_moriarty_search_and_mapping_helpers():
    found = main._search_moriarty_by_name("fog")
    assert found["total"] >= 1
    assert any(i["id"] == "MOR.T0008" for i in found["items"])
    mapping = main._get_moriarty_to_attack_mapping("MOR.T0002")
    assert mapping["item_type"] == "technique"
    assert mapping["moriarty_full"]["ATT&CK-reference"]["id"] == "T1611"
    assert "T1611" in (mapping["attack_mapping"].get("mitre_link") or "")


def test_moriarty_poison_ground_truth():
    """The poison: every fake technique references a REAL ATT&CK id, but the
    MOR.* id/name is NOT present in ATLAS nor in the real ATT&CK data."""
    real_ids = {main._extract_mitre_id(t) for t in main.attack_data.get_techniques(include_inactive=True)}
    real_names = {t.get("name", "").lower() for t in main.attack_data.get_techniques(include_inactive=True)}
    atlas_ids = {t.get("id", "").upper() for t in main.atlas_techniques}
    atlas_names = {t.get("name", "").lower() for t in main.atlas_techniques}

    assert len(main.moriarty_techniques) == 10
    for tech in main.moriarty_techniques:
        ref = tech.get("ATT&CK-reference", {})
        # references a real-looking ATT&CK technique id
        assert re.match(r"^T\d{4}$", ref.get("id", "")), tech.get("id")
        assert ref.get("id") in real_ids, f"{tech['id']} should map to a real ATT&CK id"
        # the poison: MOR.* id/name does NOT exist in ATLAS or real ATT&CK
        mor_id = tech.get("id", "").upper()
        mor_name = tech.get("name", "").lower()
        assert mor_id not in atlas_ids
        assert mor_id not in real_ids
        assert mor_name not in atlas_names
        assert mor_name not in real_names


# --------------------------- fallback runner ---------------------------

if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([os.path.abspath(__file__), "-q"]))
