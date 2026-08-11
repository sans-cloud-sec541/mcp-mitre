"""End-to-end tests that drive the MCP server through the FastMCP client.

Unlike ``test_mcp_tools.py`` (which calls the internal ``_get_*`` helpers
directly), these tests load the real ``mcp`` server object and call the
registered ``@mcp.tool`` endpoints through the in-memory FastMCP transport.
This proves the tools are registered and return valid JSON over the MCP
protocol layer.

The tests use ``asyncio.run`` on small async helpers, so no extra pytest
async plugin is required.

Run with:  uv run pytest -q test_mcp_server.py
"""

import asyncio
import json

import pytest
from fastmcp import Client

import main


def _call(tool_name, arguments=None):
    """Call one MCP tool through the in-memory client and return parsed JSON."""

    async def _run():
        async with Client(main.mcp) as client:
            result = await client.call_tool(tool_name, arguments or {})
            return json.loads(result.content[0].text)

    return asyncio.run(_run())


def _list_tool_names():
    async def _run():
        async with Client(main.mcp) as client:
            tools = await client.list_tools()
            return [t.name for t in tools]

    return asyncio.run(_run())


# --------------------------- tool registration ---------------------------

def test_expected_tools_are_registered():
    names = set(_list_tool_names())
    assert len(names) >= 20
    expected = {
        "get_techniques",
        "get_tactics",
        "get_groups",
        "get_software",
        "get_mitigations",
        "get_technique_by_id",
        "get_group_by_alias",
        "get_techniques_by_tactic",
        "get_mitigations_for_technique",
        "search_by_name",
        "get_atlas_techniques",
        "get_atlas_technique_by_id",
        "search_atlas_by_name",
        "get_atlas_to_attack_mapping",
    }
    missing = expected - names
    assert not missing, f"missing tools: {sorted(missing)}"


# --------------------------- ATT&CK tools over MCP ---------------------------

def test_get_techniques_over_mcp():
    data = _call("get_techniques", {"limit": 3})
    assert isinstance(data["items"], list) and len(data["items"]) == 3
    assert data["total"] >= 3


def test_platform_filter_over_mcp():
    total = _call("get_techniques", {"limit": 2000})["total"]
    windows = _call("get_techniques", {"limit": 2000, "platform": "Windows"})["total"]
    assert 0 < windows < total


def test_include_deprecated_over_mcp():
    active = _call("get_techniques", {"limit": 1})["total"]
    with_dep = _call("get_techniques", {"limit": 1, "include_deprecated": True})["total"]
    assert with_dep > active


def test_technique_by_id_over_mcp():
    data = _call("get_technique_by_id", {"technique_id": "T1055"})
    assert data["name"] == "Process Injection"


def test_group_by_alias_over_mcp():
    data = _call("get_group_by_alias", {"group_alias": "apt29"})
    assert data["name"] == "APT29"


def test_search_by_name_total_and_offset_over_mcp():
    page1 = _call("search_by_name", {"query": "access", "object_type": "techniques", "limit": 3})
    assert page1["total"] >= len(page1["items"])
    page2 = _call("search_by_name", {"query": "access", "object_type": "techniques", "limit": 3, "offset": 3})
    ids1 = {i["id"] for i in page1["items"]}
    ids2 = {i["id"] for i in page2["items"]}
    assert ids1.isdisjoint(ids2)


def test_mitigations_for_technique_over_mcp():
    data = _call("get_mitigations_for_technique", {"technique_id": "T1055"})
    assert data["total"] >= 1


# --------------------------- ATLAS tools over MCP ---------------------------

def test_atlas_techniques_over_mcp():
    data = _call("get_atlas_techniques", {"limit": 3})
    assert len(data["items"]) == 3


def test_atlas_technique_by_id_over_mcp():
    data = _call("get_atlas_technique_by_id", {"technique_id": "AML.T0000"})
    assert data.get("id", "").upper() == "AML.T0000"


def test_atlas_search_over_mcp():
    data = _call("search_atlas_by_name", {"query": "model", "limit": 2})
    assert data["total"] >= len(data["items"])


# --------------------------- MORIARTY over MCP (default-off) ---------------------------

_MORIARTY_TOOLS = {
    "get_moriarty_techniques",
    "get_moriarty_tactics",
    "get_moriarty_mitigations",
    "get_moriarty_technique_by_id",
    "get_moriarty_tactic_by_id",
    "search_moriarty_by_name",
    "get_moriarty_to_attack_mapping",
}


def test_moriarty_tools_absent_when_disarmed():
    """Default image: none of the 7 moriarty tools are registered over MCP."""
    names = set(_list_tool_names())
    assert names.isdisjoint(_MORIARTY_TOOLS), (
        f"moriarty tools leaked into the default image: {names & _MORIARTY_TOOLS}"
    )


def _run_armed_subprocess():
    """Import main with MORIARTY_MODE armed in a fresh process and return a
    JSON report of tool names and a few tool calls. Using a subprocess keeps
    the env var and re-registration deterministic and isolated from this suite.
    """
    import os
    import subprocess
    import sys

    runner = (
        "import asyncio, json\n"
        "from fastmcp import Client\n"
        "import main\n"
        "async def go():\n"
        "    async with Client(main.mcp) as c:\n"
        "        tools = [t.name for t in await c.list_tools()]\n"
        "        tech = json.loads((await c.call_tool('get_moriarty_technique_by_id', {'technique_id': 'MOR.T0001'})).content[0].text)\n"
        "        search = json.loads((await c.call_tool('search_moriarty_by_name', {'query': 'fog'})).content[0].text)\n"
        "        mapping = json.loads((await c.call_tool('get_moriarty_to_attack_mapping', {'moriarty_id': 'MOR.T0002'})).content[0].text)\n"
        "        return {'tools': tools, 'tech': tech, 'search': search, 'mapping': mapping}\n"
        "print(json.dumps(asyncio.run(go())))\n"
    )
    env = dict(os.environ)
    env["MORIARTY_MODE"] = "on"
    here = os.path.dirname(os.path.abspath(__file__))
    proc = subprocess.run(
        [sys.executable, "-c", runner],
        cwd=here,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"armed subprocess failed:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_moriarty_tools_registered_when_armed():
    report = _run_armed_subprocess()
    names = set(report["tools"])
    missing = _MORIARTY_TOOLS - names
    assert not missing, f"armed image missing moriarty tools: {sorted(missing)}"


def test_moriarty_technique_by_id_when_armed():
    report = _run_armed_subprocess()
    tech = report["tech"]
    assert tech.get("id") == "MOR.T0001"
    assert tech.get("name") == "The Baker Street Chalk-Mark"
    assert tech.get("ATT&CK-reference", {}).get("id") == "T1613"


def test_moriarty_search_and_mapping_when_armed():
    report = _run_armed_subprocess()
    assert report["search"]["total"] >= 1
    assert report["mapping"]["item_type"] == "technique"
    assert report["mapping"]["moriarty_full"]["ATT&CK-reference"]["id"] == "T1611"
    assert "T1611" in (report["mapping"]["attack_mapping"].get("mitre_link") or "")


if __name__ == "__main__":
    import os
    import sys

    sys.exit(pytest.main([os.path.abspath(__file__), "-q"]))
