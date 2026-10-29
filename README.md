# pan_parse.py

Extracts the **objects** and **rulebases** from a Palo Alto Networks PAN-OS firewall or Panorama XML
configuration into CSV files, preserving rule numbers, descriptions, tags and every other rule attribute.
Address, service and application groups are resolved so each rule shows the actual addresses, services and
applications it matches.

- Python 3.8+, **standard library only**, no install step
- Reads one XML file, writes a new timestamped folder per run
- Does not connect to any device and does not modify anything

Companion scripts with the same output conventions: `asa_parse.py` (Cisco ASA) and `srx_parse.py` (Juniper SRX).

---

## Contents

1. [Quick start](#1-quick-start)
2. [Input](#2-input)
3. [Command-line options](#3-command-line-options)
4. [What is parsed](#4-what-is-parsed)
5. [Output folder layout](#5-output-folder-layout)
6. [CSV output reference](#6-csv-output-reference)
7. [Behaviour notes](#7-behaviour-notes)
8. [Warnings and troubleshooting](#8-warnings-and-troubleshooting)
9. [Verifying the results](#9-verifying-the-results)
10. [Comparing runs](#10-comparing-runs)
11. [Limitations](#11-limitations)

---

## 1. Quick start

```bash
# Smoke test using the built-in sample config (no input file needed)
python pan_parse.py --selftest

# Real run
python pan_parse.py running-config.xml

# Real run with the one-row-per-source/destination/application/service CSV, failing on unresolved references
python pan_parse.py running-config.xml --expand --strict
```

Each run creates `output/<YYYY-MM-DD_HH-MM-SS>/` in the current working directory and prints its path.
Add `output/` to your `.gitignore`.

On Windows use `python` or `py`; all examples work unchanged in PowerShell or cmd.

---

## 2. Input

| Item | Detail |
|---|---|
| File | The PAN-OS XML configuration (firewall `running-config.xml`, a named snapshot, or a Panorama export) |
| Root element | `<config>`, either at the top of the file or inside a wrapper such as `<response><result>...</result></response>` |
| Tolerated noise | Text before or after the XML (for example a CLI prompt, or a wrapper that isn't valid XML) is skipped, as long as a `<config ...>` ... `</config>` block can be found |
| Not accepted | CLI `set` format, or `show config` text output. The script exits with code 2 and asks for the XML export |

### Getting the XML

- **Web UI:** *Device > Setup > Operations > Export named configuration snapshot* (choose `running-config.xml`)
  on a firewall; the same menu is on Panorama.
- **API:** the configuration export API call (`type=export&category=configuration`) returns the same XML.
- **CLI / API show:** the `show config running` response is accepted, including its `<response>` wrapper.

The script only reads objects and rules. The file also contains password hashes, keys and other secrets; none
of them are read, but remove or protect them before sharing the file.

### Supported layouts

| Layout | Scopes produced |
|---|---|
| Firewall | `shared` and each `vsys` (`vsys1`, `vsys2`, ...) |
| Panorama | `shared` and each `device-group`, including `pre-rulebase` and `post-rulebase` |

One device (`devices/entry`) per file is assumed. See [Limitations](#11-limitations).

---

## 3. Command-line options

```
python pan_parse.py [config] [-o OUTDIR] [--expand] [--max-expand N] [--strict]
                    [--csv-nl-sep STR] [--selftest]
```

| Option | Default | Description |
|---|---|---|
| `config` | (required unless `--selftest`) | Path to the XML configuration file |
| `-o`, `--outdir` | `output` | **Base** folder. Each run writes to `<outdir>/<timestamp>/` |
| `--expand` | off | Also write `rules_expanded.csv` (security rules only) |
| `--max-expand` | `100000` | Maximum expanded rows per rule. Larger rules are truncated and a warning is raised |
| `--strict` | off | Exit code 1 if any reference is unresolved |
| `--csv-nl-sep` | `" \| "` | Replacement for line breaks inside CSV fields (for example multi-line descriptions) |
| `--selftest` | off | Run against the embedded sample config; forces `--expand` |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed (warnings may still exist; see `warnings.csv`) |
| 1 | `--strict` was set and at least one reference was unresolved |
| 2 | File unreadable, not valid XML, no `<config>` element, no scopes found, or bad arguments |

Cycles and duplicate names are reported as warnings but do **not** trigger `--strict` on their own.

---

## 4. What is parsed

### Objects (per scope)

| Config element | Captured as |
|---|---|
| `address` | `ip-netmask`, `ip-range`, `fqdn` or `ip-wildcard`; description, tags, `disable-override` |
| `address-group` | Static members (names), or a dynamic filter; description, tags |
| `service` | `tcp`, `udp` and/or `sctp` with destination port(s) and source port(s); description, tags |
| `service-group` | Member names |
| `application-group` | Member names |
| `application-filter` | All filter attributes (category, subcategory, risk...) |
| `application` (custom) | All attributes |
| `tag` | Colour and comments |
| `external-list` | Type and URL; all other attributes |
| `schedule` | All schedule attributes |

### Rulebases (per scope, per position)

Every rulebase found under `rulebase` (firewall / local), `pre-rulebase` and `post-rulebase` (Panorama) is read.
Each child element that contains `rules` becomes one output file:

| Rulebase element | Output file | Column layout |
|---|---|---|
| `security` | `rules_security.csv` | Security layout |
| `default-security-rules` | `rules_default-security-rules.csv` | Security layout |
| `nat` | `rules_nat.csv` | NAT layout |
| anything else (`decryption`, `pbf`, `application-override`, `authentication`, `dos`, `qos`, `tunnel-inspect`...) | `rules_<name>.csv` | Generic layout |

Every attribute of every rule is kept. Attributes that don't have a dedicated column are written to
`other_fields` as `path=value; path=value`, so nothing is dropped.

### Reference resolution

Source, destination, service and application values are resolved wherever they appear in a rule:

| Reference | Result |
|---|---|
| Address object | Its value as configured (`10.1.1.5/32`, `10.0.0.1-10.0.0.9`) |
| FQDN / wildcard | `fqdn:example.com` / `wildcard:10.0.0.0/0.0.255.255` |
| Address group (static) | Members expanded recursively and de-duplicated |
| Address group (dynamic) | `dynamic:<filter expression>` (not expandable offline) |
| External dynamic list | `edl:<name>` |
| Literal in the rule | A typed-in IP, CIDR, range or two-letter region code is kept as is (`region:US`) |
| Service object | `tcp/443`, `tcp/80,8080-8090`, `tcp/8443 (src 1024-65535)` |
| Service group | Members expanded |
| `service-http`, `service-https` | `tcp/80`, `tcp/443` (only if not overridden by a service defined in the config) |
| `application-default`, `any` | Kept as written |
| Application group | Members expanded |
| Application filter | `filter:<name>` |
| Application not defined in the config | Treated as a predefined App-ID and kept by name (no warning) |
| Anything else not found | `unresolved:<name>` and a warning |

Lookup order for a rule's references: the rule's own scope, then its parent device-groups (Panorama), then
`shared`. The device-group hierarchy is read from `dg-meta-data` when it is present in the file.

---

## 5. Output folder layout

```
output/
  2026-10-03_09-36-16/
    objects.csv
    object_members.csv
    rules_security.csv
    rules_default-security-rules.csv   (only if present in the config)
    rules_nat.csv                      (only if present)
    rules_<other>.csv                  (one per other rulebase type found)
    rules_expanded.csv                 (only with --expand)
    warnings.csv
```

- Folder names use `YYYY-MM-DD_HH-MM-SS` in **local time**, with no characters that are illegal on Windows.
- If two runs start in the same second, the second folder gets `_2`, then `_3`, and so on. Nothing is overwritten.
- The console summary shows the hostname, config version, scopes, object counts by type, rule counts per rulebase,
  and the unresolved/warning counts, then the full path of the run folder.

All CSVs are UTF-8 with a header row, `\n` line endings and **one physical line per record**. Line breaks inside
a value (such as a multi-line rule description) are replaced with `--csv-nl-sep` (default ` | `). Multi-value cells
are joined with `;`.

---

## 6. CSV output reference

### `objects.csv`

`scope_type, scope, object_type, name, description, value_type, value, members, members_resolved, tags, disable_override, referenced_by_rules, other_fields, xpath`

| Column | Meaning |
|---|---|
| `scope_type`, `scope` | `shared`/`shared`, `vsys`/`vsys1`, or `dg`/`<device-group>` |
| `object_type` | `address`, `address-group`, `service`, `service-group`, `application-group`, `application-filter`, `application`, `tag`, `external-list`, `schedule` |
| `description` | Object description (for tags, the comments field) |
| `value_type`, `value` | Address: `ip-netmask`/`ip-range`/`fqdn`/`ip-wildcard` and its value. Dynamic group: `dynamic` and the filter. Service: protocol(s) and ports (for example `tcp` / `tcp/80,8080-8090`). Tag: `color` and the colour. External list: `url` and the URL. Filter / custom application / schedule: all attributes as `path=value; ...` |
| `members` | Direct members of a group, as configured |
| `members_resolved` | Fully flattened members (groups only) |
| `tags` | Tags applied to the object |
| `disable_override` | As configured |
| `referenced_by_rules` | `yes` if the object is reachable from any rule (see [behaviour notes](#7-behaviour-notes)), otherwise `no` |
| `other_fields` | Remaining attributes not given their own column |
| `xpath` | Location of the element in the XML |

### `object_members.csv`

`scope_type, scope, object_type, object, level, member, via`

One row per group member. `level` is `direct` (as configured) or `resolved` (flattened); `via` shows the chain
of nested groups for resolved rows, for example `ALL-DMZ>WEB-SERVERS`.

### `rules_<rulebase>.csv`

Common first columns: `scope_type, scope, rulebase_position, rulebase, rule_number, name, uuid`

| Column | Meaning |
|---|---|
| `rulebase_position` | `pre`, `local` or `post` |
| `rule_number` | 1-based position within the same scope, position and rulebase. Disabled rules are counted |
| `uuid` | The rule `uuid` attribute, if present |

Common last columns: `other_fields, xpath`

**Security layout** (`security`, `default-security-rules`), in order:
`description, tags, group_tag, audit_comment, disabled, action, rule_type, from_zones, to_zones, source, source_resolved, negate_source, source_user, source_hip, destination, destination_resolved, negate_destination, destination_hip, application, application_resolved, service, service_resolved, category, schedule, log_start, log_end, log_setting, profile_setting, qos, option`

**NAT layout** (`nat`), in order:
`description, tags, group_tag, audit_comment, disabled, nat_type, from_zones, to_zones, to_interface, source, source_resolved, destination, destination_resolved, service, service_resolved, source_translation, destination_translation, dynamic_destination_translation`

**Generic layout** (all other rulebases), in order:
`description, tags, group_tag, disabled, action, source, source_resolved, destination, destination_resolved, application, application_resolved, service, service_resolved`

Notes:
- Columns without a `_resolved` suffix show the rule as written (group names, literals). The `_resolved` columns show the
  flattened contents.
- `profile_setting`, `qos`, `option`, `source_translation`, `destination_translation` and
  `dynamic_destination_translation` hold everything under that element as `sub/path=value; ...`.
- A **blank** value means the attribute is absent from the XML, so PAN-OS applies its default. For example, a blank
  `log_end` does not mean logging is off.
- Anything not covered by a column (for example `target/...`, or the nested parts of a generic rulebase such as
  `action/forward/egress-interface`) is in `other_fields`.

### `rules_expanded.csv` (with `--expand`)

`scope_type, scope, rulebase_position, rulebase, rule_number, name, action, disabled, from_zones, to_zones, source, destination, application, service, description`

Security and default-security rules only. One row per source x destination x application x service combination.
`rule_number` repeats across the rows of the same rule. Zones are kept as the joined list from the rule. Large rules
can produce very many rows; `--max-expand` caps this per rule.

### `warnings.csv`

`scope, context, message`, where `context` is `<scope>/<position>/<rulebase>/<rule name>` for rule problems or
`group <name>` for group problems.

---

## 7. Behaviour notes

### Rule numbering and order
- `rule_number` is per scope, position and rulebase. XML document order is the rule order on the device.
- On Panorama the effective evaluation order across shared pre-rules, device-group pre-rules, local rules,
  device-group post-rules and shared post-rules is **not** computed. Use `scope`, `rulebase_position` and
  `rule_number` together if you need to reconstruct it.

### `referenced_by_rules`
An object is marked `yes` when it is reached while resolving a rule: addresses and groups in source/destination,
services, applications, tags on rules, schedules, and NAT translated addresses. Members of a used group are also
`yes`. Objects used only elsewhere (security profiles, custom URL categories, other config sections) show `no`.
Treat it as "candidate unused", not proof.

### Group resolution
- Nested groups are flattened to any depth and de-duplicated, first occurrence kept.
- Circular references are detected, reported and do not loop.
- Group names are resolved in the group's scope chain, so a device-group group can contain shared objects.

### Multi-line text
Rule and object descriptions that contain line breaks appear in CSV with the break replaced by `--csv-nl-sep`.
The XML text itself is not altered.

---

## 8. Warnings and troubleshooting

| Message (in `warnings.csv`) | Meaning / action |
|---|---|
| `unresolved address reference 'X'` | A rule or group names an address object that isn't defined in any scope in the lookup chain. For a Panorama device-group, check that the parent hierarchy is present in the file |
| `unresolved service reference 'X'` | As above for services. Only `service-http` and `service-https` are built in |
| `cycle in address group / service group / application group 'X'` | Circular nesting; the loop is broken |
| `duplicate <type> name (later definition wins)` | Two objects of the same type and scope share a name |
| `address 'X' has no value` | An address object without `ip-netmask`, `ip-range`, `fqdn` or `ip-wildcard` |
| `rule expands to N rows; truncated to M` | The expanded output hit `--max-expand` |

| Symptom | Likely cause |
|---|---|
| `ERROR: not valid XML (...)` | The file is CLI `set` format, `show config` text, or truncated. Export the XML configuration |
| `ERROR: no <config> element found` | Wrong file, or an XML export of something other than the configuration |
| `ERROR: no shared / vsys / device-group scopes found` | The file has no `shared`, `devices/entry/vsys` or `devices/entry/device-group` content |
| A rulebase is missing from the output | It has no `rules` element in the file (empty rulebases are skipped) |
| Panorama device-group references show as unresolved | Objects live in a parent device-group whose hierarchy isn't present in `dg-meta-data` in this export |
| Application names show unexpected values | Names not defined in the config are assumed to be predefined App-IDs and are left unchanged |

---

## 9. Verifying the results

The script does not compare itself with the device, so on first use:

1. **Rule counts.** Compare the console summary with the XML, for example with `xmllint`:
   ```bash
   xmllint --xpath 'count(//vsys/entry[@name="vsys1"]/rulebase/security/rules/entry)' running-config.xml
   ```
   (adjust the path for shared or device-group rulebases).
2. **Spot-check resolution.** Pick several rules that use nested groups and compare the `*_resolved` columns with the
   objects shown in the web UI.
3. **Review `warnings.csv`** and any `unresolved:` values before relying on the output.
4. Use `--strict` in scripted runs so unresolved references fail loudly.

### Loading the output

```python
import csv

rules = list(csv.DictReader(open("output/2026-10-03_09-36-16/rules_security.csv", encoding="utf-8")))
for r in rules:
    print(r["scope"], r["rulebase_position"], r["rule_number"], r["name"], r["action"], r["source_resolved"])
```

In Excel, import the CSVs as UTF-8.

---

## 10. Comparing runs

Each run is kept in its own folder, so two runs (for example before and after a change window) can be compared directly:

```bash
# Linux / macOS
diff -r output/2026-10-03_09-36-16 output/2026-10-10_09-00-02

# Windows PowerShell (or any platform with git)
git diff --no-index output/2026-10-03_09-36-16 output/2026-10-10_09-00-02
```

- Output files contain no timestamps, so identical configs produce identical CSVs.
- `rule_number` shifts for every rule below an inserted or deleted rule. Compare on `name` or `uuid`, or on the `*_resolved` columns, if you only care about content changes.
- If rule names are stable, joining on `scope, rulebase, name` is the most reliable way to match rules between runs.

Suggested `.gitignore` entry:

```
output/
```

---

## 11. Limitations

- **Not parsed:** security profiles and profile groups, custom URL categories, zones, interfaces, routing, VPN,
  GlobalProtect, templates and template stacks (Panorama), and everything outside objects and rulebases.
- **Device-group hierarchy** is read from `dg-meta-data/dg-info`. If that section is absent from the export, only the
  device group itself and `shared` are searched.
- **One device per file.** If a file contains several `devices/entry` elements, scopes with the same name overwrite
  each other.
- **Dynamic address groups and external lists** cannot be expanded offline; they appear as `dynamic:<filter>` and `edl:<name>`.
- **Custom regions** are not read; a custom region name used in a rule shows as `unresolved:` unless it is a two-letter code.
- **Application resolution** does not know the predefined App-ID list, so a misspelt predefined application is not flagged.
- **Rule numbers** are positions in the file; the script does not interpret rule hit counts, shadowing or effective order.
- **`referenced_by_rules`** only considers rules (see above).
- No automated test suite beyond `--selftest`, and no formal schema for the CSVs.
