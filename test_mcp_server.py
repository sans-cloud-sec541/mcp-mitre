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


if __name__ == "__main__":
    import os
    import sys

    sys.exit(pytest.main([os.path.abspath(__file__), "-q"]))
