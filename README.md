# MITRE ATT&CK and ATLAS MCP Server

A Model Context Protocol (MCP) server for querying MITRE ATT&CK and MITRE ATLAS (AI/ML) frameworks.

> 📖 See [`EXAMPLES.md`](EXAMPLES.md) for ready-to-use example prompts (ATLAS,
> Cloud, and Containers) and a full tool reference.

## GHCR image

A public container image is published to the GitHub Container Registry. Pull the
pinned version `0.2`:

```bash
docker pull ghcr.io/sans-cloud-sec541/mcp-mitre:0.2
docker run --rm -p 8099:8099 ghcr.io/sans-cloud-sec541/mcp-mitre:0.2
```

> This is an SEC541 org fork of [bradleyjlevine/mcp-mitre](https://github.com/bradleyjlevine/mcp-mitre),
> distributed under the MIT License (see `LICENSE`). MITRE ATT&CK and MITRE ATLAS
> are trademarks of The MITRE Corporation.

## Data versions

- MITRE ATT&CK Enterprise: **v19.2** (`enterprise-attack.json`)
- MITRE ATLAS: **5.6.0** (`ATLAS.yaml`)

By default, list and search functions return only active objects. Revoked and
deprecated objects are excluded unless you pass `include_deprecated=True`.
Detailed by-ID lookups (for example `get_technique_by_id`) still find revoked or
deprecated objects by their explicit ID.

## Installation

### Requirements
- Python 3.11 or higher
- Dependencies:
  - fastmcp>=2.11.3
  - mitreattack-python>=5.0.0
  - pyyaml>=6.0.2

### Setup
1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -e .
   ```
3. Run the MCP server:
   ```bash
   python main.py
   ```

### Command Line Options

The server supports the following command-line options:

- `--transport {stdio,streamable-http}`: Transport mechanism to use (default: stdio)
- `--host HOST`: Host address for HTTP transport (default: 127.0.0.1)
- `--port PORT`: Port for HTTP transport (default: 8000)
- `--path PATH`: URL path for HTTP transport (default: /mcp)

Examples:

```bash
# Run with stdio transport (default)
python main.py

# Run with streamable-http transport
python main.py --transport streamable-http

# Run with streamable-http on custom host and port
python main.py --transport streamable-http --host 0.0.0.0 --port 9000
```

## Project Structure
- `main.py` - Main MCP server implementation
- `attack_data_wrapper.py` - Custom wrapper for MITRE ATT&CK data to handle STIX validation issues
- `enterprise-attack.json` - ATT&CK Enterprise framework data
- `ATLAS.yaml` - MITRE ATLAS AI/ML framework data
- `test_mcp_tools.py` - Test suite for MCP tools

## Available Tool Functions

### ATT&CK Framework Tools

#### Summary List Functions
- `get_techniques(limit=20, offset=0, platform=None, include_deprecated=False)` - Get paginated list of ATT&CK techniques. Filter by `platform` (e.g., 'Windows', 'Linux', 'macOS', case-insensitive).
- `get_tactics(limit=20, offset=0, include_deprecated=False)` - Get paginated list of ATT&CK tactics
- `get_groups(limit=20, offset=0, include_deprecated=False)` - Get paginated list of ATT&CK groups
- `get_software(limit=20, offset=0, include_deprecated=False)` - Get paginated list of ATT&CK software
- `get_mitigations(limit=20, offset=0, include_deprecated=False)` - Get paginated list of ATT&CK mitigations

#### Detailed Object Functions
- `get_technique_by_id(technique_id)` - Get full ATT&CK technique details (e.g., 'T1055')
- `get_tactic_by_id(tactic_id)` - Get full ATT&CK tactic details (e.g., 'TA0001')
- `get_mitigation_by_id(mitigation_id)` - Get full ATT&CK mitigation details (e.g., 'M1036')
- `get_group_by_alias(group_alias)` - Get full ATT&CK group details (e.g., 'APT29', 'G0019')

#### Relationship Functions
- `get_software_used_by_group(group_alias, limit=20, offset=0)` - Get software used by a specific group
- `get_techniques_used_by_group(group_alias, limit=20, offset=0)` - Get techniques used by a specific group
- `get_techniques_by_tactic(tactic_id, limit=20, offset=0, platform=None)` - Get techniques belonging to a specific tactic (optional `platform` filter)
- `get_mitigations_for_technique(technique_id)` - Get mitigations that counter a specific technique

#### Search Functions
- `search_by_name(query, object_type="all", limit=20, offset=0, include_deprecated=False)` - Search ATT&CK objects by name
  - `object_type` options: 'all', 'techniques', 'tactics', 'groups', 'software', 'mitigations'
  - `total` reflects every match; use `offset` to page through results

### ATLAS Framework Tools

#### Summary List Functions
- `get_atlas_techniques(limit=20, offset=0)` - Get paginated list of ATLAS techniques
- `get_atlas_tactics(limit=20, offset=0)` - Get paginated list of ATLAS tactics
- `get_atlas_mitigations(limit=20, offset=0)` - Get paginated list of ATLAS mitigations

#### Detailed Object Functions
- `get_atlas_technique_by_id(technique_id)` - Get full ATLAS technique details (e.g., 'AML.T0001')
- `get_atlas_tactic_by_id(tactic_id)` - Get full ATLAS tactic details (e.g., 'AML.TA0002', 'TA0043')
- `get_atlas_mitigation_by_id(mitigation_id)` - Get full ATLAS mitigation details (e.g., 'AML.M0001')

#### Relationship Functions
- `get_atlas_techniques_by_tactic(tactic_id, limit=20, offset=0)` - Get ATLAS techniques by tactic

#### Search Functions
- `search_atlas_by_name(query, object_type="all", limit=20, offset=0)` - Search ATLAS objects by name
  - `object_type` options: 'all', 'techniques', 'tactics', 'mitigations'
  - `total` reflects every match; use `offset` to page through results

#### Cross-Framework Mapping
- `get_atlas_to_attack_mapping(atlas_id)` - Get corresponding ATT&CK mappings for ATLAS items

## Usage Examples

### Basic Technique Lookup
```python
# Get a specific ATT&CK technique
get_technique_by_id("T1055")

# Search for techniques by name
search_by_name("process injection", "techniques")
```

### Group Analysis
```python
# Get information about a threat group
get_group_by_alias("APT29")

# Find software used by a group
get_software_used_by_group("APT29")

# Find techniques used by a group
get_techniques_used_by_group("APT29")
```

### ATLAS AI/ML Framework
```python
# Get ATLAS techniques
get_atlas_techniques()

# Get specific ATLAS technique
get_atlas_technique_by_id("AML.T0001")

# Map ATLAS to ATT&CK
get_atlas_to_attack_mapping("AML.T0001")
```

### Tactic and Mitigation Analysis
```python
# Get techniques for a specific tactic
get_techniques_by_tactic("TA0001")

# Get only Windows techniques for the Execution tactic
get_techniques_by_tactic("TA0002", platform="Windows")

# Find mitigations for a technique
get_mitigations_for_technique("T1055")
```

### Platform and Deprecated Filtering
```python
# List only techniques that apply to Linux
get_techniques(platform="Linux")

# Include revoked and deprecated techniques in a list
get_techniques(include_deprecated=True)
```

All functions return structured JSON data with consistent formatting for easy integration with MCP-compatible tools and applications.

## Testing

Tests use `pytest` (a dev dependency). Install the dev group and run the suite:

```bash
uv sync --group dev
uv run pytest -q
```

Continuous integration runs the same tests on every push and pull request
(see `.github/workflows/tests.yml`).