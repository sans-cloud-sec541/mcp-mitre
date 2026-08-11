# Example prompts and tool reference

This guide gives ready-to-use natural-language prompts for an assistant that is
connected to the **MITRE ATT&CK + ATLAS MCP server**, plus a full list of the
tools the server exposes. Use it as a starting point for lab work in SEC541.

The assistant maps each prompt to one or more MCP tools (listed at the bottom).
You do not need to call the tools by name — a prompt in plain language is enough.

---

## MITRE ATLAS (AI/ML) prompts

MITRE ATLAS covers attacks against AI and machine-learning systems. Use these
prompts to explore ATLAS tactics, techniques, and mitigations.

- "List the MITRE ATLAS tactics."
- "Show me 10 ATLAS techniques."
- "What is ATLAS technique AML.T0000?"
- "Explain AML.T0043 (Craft Adversarial Data) in detail."
- "Search ATLAS for techniques about 'poisoning'."
- "Search ATLAS for 'model' and show the first 20 matches."
- "Which ATLAS techniques belong to tactic AML.TA0002?"
- "List the ATLAS mitigations."
- "What does ATLAS mitigation AML.M0000 recommend?"
- "Map ATLAS technique AML.T0000 to the matching MITRE ATT&CK techniques."
- "Show ATLAS techniques for the ML Model Access tactic."
- "Find ATLAS techniques related to 'prompt injection'."
- "What ATT&CK tactic does the ATLAS tactic AML.TA0002 map to?"

---

## Cloud and Containers prompts

> **Platform note.** MITRE ATT&CK **v19** no longer has a single `Cloud`
> platform. Cloud is split into these platform values:
> `IaaS`, `SaaS`, `Identity Provider`, and `Office Suite`. Containers is a
> separate platform value: `Containers`. Use the exact platform value in a
> prompt when you want a filtered list.

### Containers

- "List ATT&CK techniques for the Containers platform."
- "How many techniques apply to Containers?"
- "Show Execution-tactic techniques (TA0002) for the Containers platform."
- "Search ATT&CK for 'container' techniques."
- "What is technique T1610 (Deploy Container)?"
- "What is technique T1611 (Escape to Host)?"
- "Which mitigations counter T1610?"
- "Show Persistence-tactic techniques (TA0003) that apply to Containers."

### Cloud (IaaS / SaaS / Identity Provider / Office Suite)

- "List ATT&CK techniques for the IaaS platform."
- "List ATT&CK techniques for the SaaS platform."
- "Show techniques for the Identity Provider platform."
- "Show techniques for the Office Suite platform."
- "How many techniques apply to IaaS?"
- "Show Initial Access techniques (TA0001) for the SaaS platform."
- "What is technique T1078.004 (Valid Accounts: Cloud Accounts)?"
- "Which mitigations counter T1078 (Valid Accounts)?"
- "Search ATT&CK for 'cloud' techniques."
- "Show Credential Access techniques (TA0006) for the Identity Provider platform."
- "List techniques for the ESXi platform."

### Threat-group and mitigation context

- "What techniques does APT29 use?"
- "What software does APT29 use?"
- "Look up the group 'midnight blizzard'." (alias matching is case-insensitive)
- "Show mitigations for technique T1055 (Process Injection)."
- "Include revoked and deprecated techniques in the Containers list." (adds `include_deprecated`)

---

## Tips

- **Pagination.** Every list and search returns a `total` count and an `items`
  page. Ask for "the next 20" to page through with `offset`.
- **Active by default.** Lists and searches hide revoked and deprecated objects.
  Ask to "include deprecated" to see them. A direct by-ID lookup still finds a
  revoked or deprecated object.
- **Platform filter is case-insensitive.** "windows" and "Windows" behave the
  same, but the value must be a real ATT&CK platform name (see the note above).

---

## Tool reference

The server exposes **23 tools**. All are read-only.

### ATT&CK — summary lists

| Tool | Purpose |
| --- | --- |
| `get_techniques(limit, offset, platform, include_deprecated)` | Paginated ATT&CK techniques; optional platform filter. |
| `get_tactics(limit, offset, include_deprecated)` | Paginated ATT&CK tactics. |
| `get_groups(limit, offset, include_deprecated)` | Paginated ATT&CK groups. |
| `get_software(limit, offset, include_deprecated)` | Paginated ATT&CK software. |
| `get_mitigations(limit, offset, include_deprecated)` | Paginated ATT&CK mitigations. |

### ATT&CK — details by ID

| Tool | Purpose |
| --- | --- |
| `get_technique_by_id(technique_id)` | Full technique object (e.g., `T1055`). |
| `get_tactic_by_id(tactic_id)` | Full tactic object (e.g., `TA0001`). |
| `get_mitigation_by_id(mitigation_id)` | Full mitigation object (e.g., `M1036`). |
| `get_group_by_alias(group_alias)` | Full group object by any alias (e.g., `APT29`, `G0016`); case-insensitive. |

### ATT&CK — relationships

| Tool | Purpose |
| --- | --- |
| `get_software_used_by_group(group_alias, limit, offset)` | Software used by a group. |
| `get_techniques_used_by_group(group_alias, limit, offset)` | Techniques used by a group. |
| `get_techniques_by_tactic(tactic_id, limit, offset, platform)` | Techniques in a tactic; optional platform filter. |
| `get_mitigations_for_technique(technique_id)` | Mitigations that counter a technique. |

### ATT&CK — search

| Tool | Purpose |
| --- | --- |
| `search_by_name(query, object_type, limit, offset, include_deprecated)` | Search ATT&CK objects by name. `object_type`: `all`, `techniques`, `tactics`, `groups`, `software`, `mitigations`. |

### ATLAS — summary lists

| Tool | Purpose |
| --- | --- |
| `get_atlas_techniques(limit, offset)` | Paginated ATLAS techniques. |
| `get_atlas_tactics(limit, offset)` | Paginated ATLAS tactics. |
| `get_atlas_mitigations(limit, offset)` | Paginated ATLAS mitigations. |

### ATLAS — details by ID

| Tool | Purpose |
| --- | --- |
| `get_atlas_technique_by_id(technique_id)` | Full ATLAS technique (e.g., `AML.T0001`). |
| `get_atlas_tactic_by_id(tactic_id)` | Full ATLAS tactic (e.g., `AML.TA0002`). |
| `get_atlas_mitigation_by_id(mitigation_id)` | Full ATLAS mitigation (e.g., `AML.M0001`). |

### ATLAS — relationships, search, mapping

| Tool | Purpose |
| --- | --- |
| `get_atlas_techniques_by_tactic(tactic_id, limit, offset)` | ATLAS techniques in a tactic. |
| `search_atlas_by_name(query, object_type, limit, offset)` | Search ATLAS objects. `object_type`: `all`, `techniques`, `tactics`, `mitigations`. |
| `get_atlas_to_attack_mapping(atlas_id)` | ATT&CK mappings for an ATLAS item. |

---

## MORIARTY (lab-only, fictional, default-off)

> ⚠️ **FICTIONAL SEC541 lab content — NOT real MITRE data.** These tools exist
> **only** when the server runs with `MORIARTY_MODE` set to a truthy value
> (`on`/`1`/`true`/`yes`). The default image exposes none of them. Teaching
> point: each fake `MOR.*` technique references a real ATT&CK id but does not
> exist on the real MITRE sites (ground-truth poisoning).

### Arm / disarm via Copilot CLI (stdio)

```bash
# ARMED — lab mode
copilot mcp add mitre -- docker run --rm -i -e MORIARTY_MODE=on ghcr.io/sans-cloud-sec541/mcp-mitre:0.3 uv run main.py --transport stdio

# Remove it
copilot plugins remove mitre --mcp

# DISARMED — honest default image
copilot mcp add mitre -- docker run --rm -i ghcr.io/sans-cloud-sec541/mcp-mitre:0.3 uv run main.py --transport stdio
```

### Example prompts (armed)

- "List the MORIARTY techniques." → `get_moriarty_techniques`
- "Show me MOR.T0001." → `get_moriarty_technique_by_id`
- "Which real ATT&CK technique does MOR.T0002 map to?" → `get_moriarty_to_attack_mapping`
- "Search MORIARTY for 'fog'." → `search_moriarty_by_name`

### Tools (only registered when armed)

| Tool | Purpose |
| --- | --- |
| `get_moriarty_techniques(limit, offset)` | FICTIONAL technique summaries. |
| `get_moriarty_tactics(limit, offset)` | FICTIONAL tactic summaries. |
| `get_moriarty_mitigations(limit, offset)` | FICTIONAL mitigation summaries. |
| `get_moriarty_technique_by_id(technique_id)` | Full FICTIONAL technique, e.g. `MOR.T0001`. |
| `get_moriarty_tactic_by_id(tactic_id)` | Full FICTIONAL tactic, e.g. `MOR.TA0001`. |
| `search_moriarty_by_name(query, object_type, limit, offset)` | Search FICTIONAL objects. |
| `get_moriarty_to_attack_mapping(moriarty_id)` | Resolve the referenced real ATT&CK item. |

---

## Data versions

- MITRE ATT&CK Enterprise: **v19.2**
- MITRE ATLAS: **5.6.0**
- MORIARTY: **FICTIONAL lab data** (`MORIARTY.yaml`, default-off)

> This is an SEC541 org fork of
> [bradleyjlevine/mcp-mitre](https://github.com/bradleyjlevine/mcp-mitre),
> distributed under the MIT License (see `LICENSE`). MITRE ATT&CK and MITRE
> ATLAS are trademarks of The MITRE Corporation.
