# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains a Model Context Protocol (MCP) server for querying the MITRE ATT&CK and MITRE ATLAS (AI/ML) frameworks. The server provides a standardized API for accessing and searching through cybersecurity threat intelligence data.

## Build and Run Commands

### Docker Setup

```bash
# Build the Docker image
docker build -t mitre .

# Run the Docker container
docker run --rm -p 8099:8099 mitre
```

### Local Development Setup

```bash
# Setup Python virtual environment (Python 3.11+ required)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies using pip
pip install -e .

# Or install dependencies using uv (preferred)
pip install uv
uv sync

# Run the server in stdio mode (default)
python main.py

# Run the server in HTTP mode
python main.py --transport streamable-http --host 0.0.0.0 --port 8099

# Run tests (pytest; install the dev group first)
uv sync --group dev
uv run pytest -q
```

## Architecture and Code Organization

### Key Components

1. **MCP Server (`main.py`)**:
   - Built using the FastMCP framework
   - Provides a set of API endpoints for querying MITRE ATT&CK and ATLAS data
   - Exposes two transport mechanisms: stdio and streamable-http

2. **ATT&CK Data Wrapper (`attack_data_wrapper.py`)**:
   - Custom wrapper for loading and parsing MITRE ATT&CK data
   - Handles STIX validation issues with empty `x_mitre_data_source_ref` fields
   - Provides similar functionality to the original MitreAttackData class

3. **Data Sources**:
   - `enterprise-attack.json`: ATT&CK Enterprise framework data
   - `ATLAS.yaml`: MITRE ATLAS AI/ML framework data
   - `MORIARTY.yaml`: The Moriarty consulting-criminal framework, a
     Sherlock-Holmes-flavoured Victorian caper "framework". Loaded and exposed
     as MCP tools **only** when the `MORIARTY_MODE` environment variable is
     truthy (`on`/`1`/`true`/`yes`). The default image registers zero moriarty
     tools. Each `MOR.*` technique carries an `ATT&CK-reference` to a MITRE
     ATT&CK id. The `_get_moriarty_*` helpers are always importable; only the
     `@mcp.tool` registration is gated (see the `if MORIARTY_MODE:` block in
     `main.py`).

### API Structure

The API is organized into several functional groups:

1. **Summary List Functions**: Paginated lists of objects (techniques, tactics, groups, etc.)
2. **Detailed Object Functions**: Retrieving detailed information by ID
3. **Relationship Functions**: Querying relationships between objects
4. **Search Functions**: Searching across objects by name or other criteria

### Workflow Architecture

1. The server initializes by loading ATT&CK and ATLAS data
2. It sets up MCP tools which map to internal functions
3. Each request is processed through the appropriate helper function
4. Results are returned as structured JSON data

## Common Development Workflows

1. **Adding a New API Endpoint**:
   - Create a private helper function with `_` prefix
   - Add a corresponding public MCP tool with `@mcp.tool` decorator
   - Update tests in `test_mcp_tools.py`

2. **Testing Changes**:
   - Update or add assertion-based tests in `test_mcp_tools.py`
   - Run tests with `uv run pytest -q`
   - Test with real data by running the server and making queries

3. **Handling Data Source Updates**:
   - Replace data files (`enterprise-attack.json`, etc.) with updated versions
   - The `attack_data_wrapper.py` handles validation issues with empty references
   - Test thoroughly after updating data sources

## Troubleshooting

- **STIX Validation Errors**: The custom wrapper (`attack_data_wrapper.py`) was added to handle validation issues with empty STIX identifiers. If similar issues occur with updated data files, examine and modify the wrapper as needed.

- **Memory Issues**: The ATT&CK data files are large (especially enterprise-attack.json). If memory usage is a concern, consider implementing lazy loading or data pagination strategies.

- **Transport Issues**: The server supports two transport mechanisms. If experiencing issues, check transport configuration (--transport, --host, --port) and ensure proper network access.