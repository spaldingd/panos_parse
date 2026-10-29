#!/usr/bin/env python3
"""
panos_parse.py - Extract objects and rulebases from a Palo Alto Networks PAN-OS / Panorama
XML configuration and write them to CSV.

Standard library only (Python 3.8+).

Usage:
    python panos_parse.py config.xml [-o output] [--expand] [--max-expand N] [--strict]
                        [--csv-nl-sep STR]
    python panos_parse.py --selftest          # run against the embedded sample config

Each run writes to <output>/<YYYY-MM-DD_HH-MM-SS>/ (a new folder per run; add "output/" to
.gitignore):
    objects.csv            one row per object (address, groups, services, apps, tags, ...)
    object_members.csv     direct and fully-resolved members of every group
    rules_<rulebase>.csv   one file per rulebase found (security, nat, decryption, pbf, ...)
    rules_expanded.csv     (--expand) security rules: one row per src x dst x app x service
    warnings.csv           unresolved references, cycles, duplicates

Scopes handled: shared, every vsys (firewall) and every device-group (Panorama, pre and post
rulebases). Object references are resolved against the rule's own scope first, then parent
device-groups (if the hierarchy is present in the file), then shared.
"""
import argparse
import csv
import itertools
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

TOOL_VERSION = "0.1.0"

OBJECT_TAGS = ["address", "address-group", "service", "service-group", "application-group",
               "application-filter", "application", "tag", "external-list", "schedule"]
RULEBASE_POSITIONS = [("pre-rulebase", "pre"), ("rulebase", "local"), ("post-rulebase", "post")]
ADDR_TYPES = ("ip-netmask", "ip-range", "fqdn", "ip-wildcard")
BUILTIN_SERVICES = {"service-http": "tcp/80", "service-https": "tcp/443",
                    "application-default": "application-default", "any": "any"}

IP4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2}|-\d{1,3}(\.\d{1,3}){3})?$")
IP6_RE = re.compile(r"^[0-9A-Fa-f:.]+(/\d{1,3})?(-[0-9A-Fa-f:.]+)?$")
REGION_RE = re.compile(r"^[A-Z]{2}$")

CSV_NL_SEP = [" | "]
_NL_RE = re.compile(r"\r\n|\r|\n")

# --------------------------------------------------------------------------- #
# Rule column specifications: (csv column, kind, config key)
#   list   -> values of that key joined with ';'
#   res    -> resolved values (groups expanded) for that key
#   prefix -> everything under that key, as "subkey=value; ..."
# Anything not claimed by a column ends up in other_fields, so nothing is dropped.
# --------------------------------------------------------------------------- #
SECURITY = [
    ("description", "list", "description"), ("tags", "list", "tag"), ("group_tag", "list", "group-tag"),
    ("audit_comment", "list", "audit-comment"), ("disabled", "list", "disabled"),
    ("action", "list", "action"), ("rule_type", "list", "rule-type"),
    ("from_zones", "list", "from"), ("to_zones", "list", "to"),
    ("source", "list", "source"), ("source_resolved", "res", "source"),
    ("negate_source", "list", "negate-source"), ("source_user", "list", "source-user"),
    ("source_hip", "list", "source-hip"),
    ("destination", "list", "destination"), ("destination_resolved", "res", "destination"),
    ("negate_destination", "list", "negate-destination"), ("destination_hip", "list", "destination-hip"),
    ("application", "list", "application"), ("application_resolved", "res", "application"),
    ("service", "list", "service"), ("service_resolved", "res", "service"),
    ("category", "list", "category"), ("schedule", "list", "schedule"),
    ("log_start", "list", "log-start"), ("log_end", "list", "log-end"),
    ("log_setting", "list", "log-setting"),
    ("profile_setting", "prefix", "profile-setting"), ("qos", "prefix", "qos"),
    ("option", "prefix", "option"),
]
NAT = [
    ("description", "list", "description"), ("tags", "list", "tag"), ("group_tag", "list", "group-tag"),
    ("audit_comment", "list", "audit-comment"), ("disabled", "list", "disabled"),
    ("nat_type", "list", "nat-type"),
    ("from_zones", "list", "from"), ("to_zones", "list", "to"), ("to_interface", "list", "to-interface"),
    ("source", "list", "source"), ("source_resolved", "res", "source"),
    ("destination", "list", "destination"), ("destination_resolved", "res", "destination"),
    ("service", "list", "service"), ("service_resolved", "res", "service"),
    ("source_translation", "prefix", "source-translation"),
    ("destination_translation", "prefix", "destination-translation"),
    ("dynamic_destination_translation", "prefix", "dynamic-destination-translation"),
]
GENERIC = [
    ("description", "list", "description"), ("tags", "list", "tag"), ("group_tag", "list", "group-tag"),
    ("disabled", "list", "disabled"), ("action", "list", "action"),
    ("source", "list", "source"), ("source_resolved", "res", "source"),
    ("destination", "list", "destination"), ("destination_resolved", "res", "destination"),
    ("application", "list", "application"), ("application_resolved", "res", "application"),
    ("service", "list", "service"), ("service_resolved", "res", "service"),
]
SPECS = {"security": SECURITY, "default-security-rules": SECURITY, "nat": NAT}
RULE_BASE_COLS = ["scope_type", "scope", "rulebase_position", "rulebase", "rule_number", "name", "uuid"]

OBJECT_COLS = ["scope_type", "scope", "object_type", "name", "description", "value_type", "value",
               "members", "members_resolved", "tags", "disable_override", "referenced_by_rules",
               "other_fields", "xpath"]
EXPANDED_COLS = ["scope_type", "scope", "rulebase_position", "rulebase", "rule_number", "name", "action",
                 "disabled", "from_zones", "to_zones", "source", "destination", "application",
                 "service", "description"]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def txt(el):
    return (el.text or "").strip()


def flatten(el, prefix="", out=None):
    """Flatten an element into {path: [values]}.  <member> children become list items,
    named <entry> children contribute their name, nested elements become 'a/b/c' paths."""
    if out is None:
        out = {}
    for ch in el:
        if ch.tag == "member":
            out.setdefault(prefix.rstrip("/"), []).append(txt(ch))
        elif ch.tag == "entry":
            name = ch.get("name", "")
            if len(ch):
                flatten(ch, "%sentry[%s]/" % (prefix, name), out)
            else:
                out.setdefault(prefix + "entry", []).append(name)
        elif len(ch) == 0:
            out.setdefault(prefix + ch.tag, []).append(txt(ch))
        else:
            flatten(ch, prefix + ch.tag + "/", out)
    return out


def kv(items):
    return "; ".join("%s=%s" % (k, ";".join(v)) for k, v in items)


def pop_prefix(rem, prefix):
    found = []
    for k in list(rem):
        if k == prefix or k.startswith(prefix + "/"):
            found.append((k[len(prefix) + 1:] if k != prefix else k, rem.pop(k)))
    return found


def looks_literal(v):
    return bool(IP4_RE.match(v) or (":" in v and IP6_RE.match(v)) or REGION_RE.match(v))


def uniq(pairs):
    seen, out = set(), []
    for text, via in pairs:
        if text not in seen:
            seen.add(text)
            out.append((text, via))
    return out


def service_text(proto, port, src):
    t = "%s/%s" % (proto, port or "")
    return t + (" (src %s)" % src if src else "")


def find_config(root):
    if root.tag == "config":
        return root
    c = root.find(".//config")
    if c is None:
        raise ValueError("no <config> element found in the XML")
    return c


def load_xml(path):
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        return ET.fromstring(data)
    except ET.ParseError as first:
        # Tolerate wrapper text / CLI noise around the XML
        text = data.decode("utf-8", errors="replace")
        s, e = text.find("<config"), text.rfind("</config>")
        if s >= 0 and e > s:
            try:
                return ET.fromstring(text[s:e + len("</config>")])
            except ET.ParseError:
                pass
        raise ValueError("not valid XML (%s). If this is CLI 'set' format or "
                         "'show config' text, export the XML configuration instead." % first)


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class PanParser:
    def __init__(self, expand=False, max_expand=100000):
        self.expand, self.max_expand = expand, max_expand
        self.scopes = {}      # (type, name) -> {"objs": {type: {name: obj}}, "el":..., "path":...}
        self.parent = {}      # device-group -> parent device-group
        self.used = set()
        self.views = {}       # (scope, type, name) -> [(text, via)]
        self.warnings = []
        self._wseen = set()
        self.unresolved = 0
        self.rule_rows = {}   # rulebase -> [row]
        self.expanded = []
        self.meta = {"hostname": None, "version": None}
        self.object_rows = []
        self.member_rows = []

    # ---- diagnostics ----------------------------------------------------- #
    def warn(self, scope, ctx, msg):
        key = (scope, ctx, msg)
        if key not in self._wseen:
            self._wseen.add(key)
            self.warnings.append({"scope": scope, "context": ctx, "message": msg})

    def unres(self, kind, name, sk, ctx):
        self.unresolved += 1
        self.warn(sk[1], ctx, "unresolved %s reference '%s'" % (kind, name))

    # ---- ingest ---------------------------------------------------------- #
    def parse(self, root):
        cfg = find_config(root)
        self.meta["version"] = cfg.get("version") or cfg.get("detail-version")
        h = cfg.find("devices/entry/deviceconfig/system/hostname")
        self.meta["hostname"] = txt(h) if h is not None else None

        for info in cfg.findall(".//dg-meta-data/dg-info/entry"):
            p = info.find("parent-dg")
            if p is not None and txt(p):
                self.parent[info.get("name")] = txt(p)

        shared = cfg.find("shared")
        if shared is not None:
            self.add_scope(("shared", "shared"), shared, "config/shared")
        for dev in cfg.findall("devices/entry"):
            dpath = "config/devices/entry[@name='%s']" % dev.get("name", "")
            for v in dev.findall("vsys/entry"):
                self.add_scope(("vsys", v.get("name", "")), v, "%s/vsys/entry[@name='%s']" % (dpath, v.get("name", "")))
            for dg in dev.findall("device-group/entry"):
                self.add_scope(("dg", dg.get("name", "")), dg,
                               "%s/device-group/entry[@name='%s']" % (dpath, dg.get("name", "")))
        if not self.scopes:
            raise ValueError("no shared / vsys / device-group scopes found in config")

        self.compute_group_views()
        for sk, sc in self.scopes.items():
            self.process_rulebases(sk, sc)
        self.build_object_rows()

    def add_scope(self, sk, el, path):
        sc = {"objs": {t: {} for t in OBJECT_TAGS}, "el": el, "path": path}
        self.scopes[sk] = sc
        for t in OBJECT_TAGS:
            cont = el.find(t)
            if cont is None:
                continue
            for e in cont.findall("entry"):
                name = e.get("name", "")
                if name in sc["objs"][t]:
                    self.warn(sk[1], "%s/%s" % (t, name), "duplicate %s name (later definition wins)" % t)
                sc["objs"][t][name] = {"type": t, "name": name, "scope": sk, "fields": flatten(e),
                                       "xpath": "%s/%s/entry[@name='%s']" % (path, t, name)}

    # ---- lookup & resolution --------------------------------------------- #
    def chain(self, sk):
        out, cur, seen = [], sk, set()
        while cur and cur not in seen:
            seen.add(cur)
            out.append(cur)
            cur = ("dg", self.parent[cur[1]]) if cur[0] == "dg" and cur[1] in self.parent else None
        if ("shared", "shared") not in out:
            out.append(("shared", "shared"))
        return out

    def lookup(self, types, name, sk):
        for k in self.chain(sk):
            sc = self.scopes.get(k)
            if sc:
                for t in types:
                    o = sc["objs"][t].get(name)
                    if o:
                        return o
        return None

    def mark(self, o):
        self.used.add((o["scope"], o["type"], o["name"]))

    def resolve_address(self, name, sk, ctx, path=()):
        if name == "any":
            return [("any", list(path))]
        o = self.lookup(("address", "address-group", "external-list"), name, sk)
        if o is None:
            if looks_literal(name):
                return [(("region:" + name) if REGION_RE.match(name) else name, list(path))]
            self.unres("address", name, sk, ctx)
            return [("unresolved:" + name, list(path) + [name])]
        if name in path:
            self.warn(sk[1], ctx, "cycle in address group '%s'" % name)
            return []
        self.mark(o)
        via, f, out = list(path) + [name], o["fields"], []
        if o["type"] == "address":
            for vt in ADDR_TYPES:
                if vt in f:
                    v = ";".join(f[vt])
                    text = v if vt in ("ip-netmask", "ip-range") else "%s:%s" % (vt.replace("ip-", ""), v)
                    return [(text, via)]
            self.warn(sk[1], ctx, "address '%s' has no value" % name)
            return [(name, via)]
        if o["type"] == "address-group":
            for m in f.get("static", []):
                out += self.resolve_address(m, sk, ctx, tuple(via))
            if "dynamic/filter" in f:
                out.append(("dynamic:" + ";".join(f["dynamic/filter"]), via))
            return uniq(out)
        return [("edl:" + name, via)]

    def resolve_service(self, name, sk, ctx, path=()):
        if name in BUILTIN_SERVICES and self.lookup(("service", "service-group"), name, sk) is None:
            return [(BUILTIN_SERVICES[name], list(path))]
        o = self.lookup(("service", "service-group"), name, sk)
        if o is None:
            self.unres("service", name, sk, ctx)
            return [("unresolved:" + name, list(path) + [name])]
        if name in path:
            self.warn(sk[1], ctx, "cycle in service group '%s'" % name)
            return []
        self.mark(o)
        via, f = list(path) + [name], o["fields"]
        if o["type"] == "service":
            texts = []
            for proto in ("tcp", "udp", "sctp"):
                p, s = f.get("protocol/%s/port" % proto), f.get("protocol/%s/source-port" % proto)
                if p is not None or s is not None:
                    texts.append(service_text(proto, ";".join(p or []), ";".join(s or [])))
            return [(t, via) for t in texts] or [(name, via)]
        out = []
        for m in f.get("members", []):
            out += self.resolve_service(m, sk, ctx, tuple(via))
        return uniq(out)

    def resolve_app(self, name, sk, ctx, path=()):
        if name == "any":
            return [("any", list(path))]
        o = self.lookup(("application-group", "application-filter", "application"), name, sk)
        if o is None:        # predefined App-ID: not defined in the config file
            return [(name, list(path))]
        if name in path:
            self.warn(sk[1], ctx, "cycle in application group '%s'" % name)
            return []
        self.mark(o)
        via = list(path) + [name]
        if o["type"] == "application-group":
            out = []
            for m in o["fields"].get("members", []):
                out += self.resolve_app(m, sk, ctx, tuple(via))
            return uniq(out)
        return [(("filter:" if o["type"] == "application-filter" else "") + name, via)]

    def compute_group_views(self):
        saved, self.used = self.used, set()
        fns = (("address-group", self.resolve_address), ("service-group", self.resolve_service),
               ("application-group", self.resolve_app))
        for sk, sc in self.scopes.items():
            for t, fn in fns:
                for name in sc["objs"][t]:
                    self.views[(sk, t, name)] = fn(name, sk, "group %s" % name)
        self.used = saved

    # ---- rulebases ------------------------------------------------------- #
    def process_rulebases(self, sk, sc):
        for rbtag, position in RULEBASE_POSITIONS:
            rb = sc["el"].find(rbtag)
            if rb is None:
                continue
            for rtype in rb:
                rules = rtype.find("rules")
                if rules is None:
                    continue
                for idx, e in enumerate(rules.findall("entry"), 1):
                    xp = "%s/%s/%s/rules/entry[@name='%s']" % (sc["path"], rbtag, rtype.tag, e.get("name", ""))
                    self.process_rule(sk, position, rtype.tag, idx, e, xp)

    def process_rule(self, sk, position, rbname, idx, entry, xpath):
        f = flatten(entry)
        name = entry.get("name", "")
        ctx = "%s/%s/%s/%s" % (sk[1], position, rbname, name)

        resolved = {}
        for field, fn in (("source", self.resolve_address), ("destination", self.resolve_address),
                          ("service", self.resolve_service), ("application", self.resolve_app)):
            if field in f:
                out = []
                for v in f[field]:
                    out += fn(v, sk, ctx)
                resolved[field] = [t for t, _ in uniq(out)]
        for t in f.get("tag", []):
            o = self.lookup(("tag",), t, sk)
            if o:
                self.mark(o)
        for s in f.get("schedule", []):
            o = self.lookup(("schedule",), s, sk)
            if o:
                self.mark(o)
        for k, vals in f.items():                       # NAT translated addresses count as usage
            if k.endswith("translated-address"):
                for v in vals:
                    if self.lookup(("address", "address-group"), v, sk):
                        self.resolve_address(v, sk, ctx)

        spec = SPECS.get(rbname, GENERIC)
        rem = dict(f)
        row = {"scope_type": sk[0], "scope": sk[1], "rulebase_position": position, "rulebase": rbname,
               "rule_number": idx, "name": name, "uuid": entry.get("uuid") or ";".join(rem.pop("uuid", []))}
        for col, kind, key in spec:
            if kind == "list":
                row[col] = ";".join(rem.pop(key, []))
            elif kind == "res":
                row[col] = ";".join(resolved.get(key, []))
            else:
                row[col] = kv(pop_prefix(rem, key))
        row["other_fields"] = kv(rem.items())
        row["xpath"] = xpath
        self.rule_rows.setdefault(rbname, []).append(row)

        if self.expand and spec is SECURITY:
            lists = [resolved.get(k) or [""] for k in ("source", "destination", "application", "service")]
            total = 1
            for l in lists:
                total *= len(l)
            if total > self.max_expand:
                self.warn(sk[1], ctx, "rule expands to %d rows; truncated to %d" % (total, self.max_expand))
            for s, d, a, v in itertools.islice(itertools.product(*lists), self.max_expand):
                r = {k: row.get(k, "") for k in EXPANDED_COLS}
                r.update({"source": s, "destination": d, "application": a, "service": v})
                self.expanded.append(r)

    # ---- objects --------------------------------------------------------- #
    def build_object_rows(self):
        for sk, sc in self.scopes.items():
            for t in OBJECT_TAGS:
                for name, o in sc["objs"][t].items():
                    f = dict(o["fields"])
                    desc = ";".join(f.pop("description", []))
                    comments = ";".join(f.pop("comments", []))
                    tags = ";".join(f.pop("tag", []))
                    override = ";".join(f.pop("disable-override", []))
                    members, vt, val = [], "", ""
                    if t == "address":
                        for k in ADDR_TYPES:
                            if k in f:
                                vt, val = k, ";".join(f.pop(k))
                                break
                    elif t == "address-group":
                        members = f.pop("static", [])
                        if "dynamic/filter" in f:
                            vt, val = "dynamic", ";".join(f.pop("dynamic/filter"))
                    elif t in ("service-group", "application-group"):
                        members = f.pop("members", [])
                    elif t == "service":
                        texts, protos = [], []
                        for proto in ("tcp", "udp", "sctp"):
                            p, s = f.pop("protocol/%s/port" % proto, None), f.pop("protocol/%s/source-port" % proto, None)
                            if p is not None or s is not None:
                                protos.append(proto)
                                texts.append(service_text(proto, ";".join(p or []), ";".join(s or [])))
                        vt, val = "/".join(protos), "; ".join(texts)
                    elif t == "tag":
                        vt, val = "color", ";".join(f.pop("color", []))
                        desc = desc or comments
                    elif t == "external-list":
                        for k in list(f):
                            if k.endswith("/url"):
                                vt, val = "url", ";".join(f.pop(k))
                                break
                    else:
                        val = kv(f.items())
                        f = {}
                    if t != "tag" and comments:
                        f["comments"] = [comments]
                    view = self.views.get((sk, t, name))
                    referenced = ""
                    if t in ("address", "address-group", "service", "service-group", "application-group",
                             "application-filter", "application", "tag", "schedule", "external-list"):
                        referenced = "yes" if (sk, t, name) in self.used else "no"
                    self.object_rows.append({
                        "scope_type": sk[0], "scope": sk[1], "object_type": t, "name": name,
                        "description": desc, "value_type": vt, "value": val, "members": ";".join(members),
                        "members_resolved": ";".join(x for x, _ in view) if view else "",
                        "tags": tags, "disable_override": override, "referenced_by_rules": referenced,
                        "other_fields": kv(f.items()), "xpath": o["xpath"]})
                    for m in members:
                        self.member_rows.append({"scope_type": sk[0], "scope": sk[1], "object_type": t,
                                                 "object": name, "level": "direct", "member": m, "via": ""})
                    for text, via in (view or []):
                        self.member_rows.append({"scope_type": sk[0], "scope": sk[1], "object_type": t,
                                                 "object": name, "level": "resolved", "member": text,
                                                 "via": ">".join(via)})


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def write_csv(path, fields, rows):
    """One physical line per record: embedded line breaks are replaced with CSV_NL_SEP."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: (_NL_RE.sub(CSV_NL_SEP[0], v) if isinstance(v, str) else v) for k, v in r.items()})


def make_run_dir(base):
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path, n = os.path.join(base, stamp), 1
    while True:
        try:
            os.makedirs(path)
            return path
        except FileExistsError:
            n += 1
            path = os.path.join(base, "%s_%d" % (stamp, n))


def write_outputs(p, run_dir):
    write_csv(os.path.join(run_dir, "objects.csv"), OBJECT_COLS, p.object_rows)
    write_csv(os.path.join(run_dir, "object_members.csv"),
              ["scope_type", "scope", "object_type", "object", "level", "member", "via"], p.member_rows)
    for rb, rows in p.rule_rows.items():
        cols = RULE_BASE_COLS + [c for c, _, _ in SPECS.get(rb, GENERIC)] + ["other_fields", "xpath"]
        write_csv(os.path.join(run_dir, "rules_%s.csv" % rb), cols, rows)
    if p.expand:
        write_csv(os.path.join(run_dir, "rules_expanded.csv"), EXPANDED_COLS, p.expanded)
    write_csv(os.path.join(run_dir, "warnings.csv"), ["scope", "context", "message"], p.warnings)


def print_summary(p):
    print("Device        : %s (config version %s)" % (p.meta["hostname"], p.meta["version"]))
    print("Scopes        : %s" % ", ".join("%s:%s" % k for k in p.scopes))
    counts = {}
    for r in p.object_rows:
        counts[r["object_type"]] = counts.get(r["object_type"], 0) + 1
    print("Objects       : %d  (%s)" % (len(p.object_rows), ", ".join("%s=%d" % kv_ for kv_ in counts.items())))
    for rb, rows in p.rule_rows.items():
        print("Rules         : %-24s %d" % (rb, len(rows)))
    print("Unresolved refs: %d   Warnings: %d" % (p.unresolved, len(p.warnings)))


# --------------------------------------------------------------------------- #
SAMPLE = """<?xml version="1.0"?>
<config version="10.1.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-FW01</hostname></system></deviceconfig>
      <vsys>
        <entry name="vsys1">
          <tag>
            <entry name="web"><color>color1</color><comments>Web tier</comments></entry>
            <entry name="partner"><color>color5</color></entry>
          </tag>
          <address>
            <entry name="WEB1"><ip-netmask>10.1.1.5/32</ip-netmask><description>Web server 1</description>
              <tag><member>web</member></tag></entry>
            <entry name="WEB2"><ip-netmask>10.1.1.6</ip-netmask></entry>
            <entry name="DMZ-NET"><ip-netmask>10.1.1.0/24</ip-netmask></entry>
            <entry name="PARTNER-RANGE"><ip-range>203.0.113.10-203.0.113.20</ip-range></entry>
            <entry name="LOOKUP"><fqdn>example.com</fqdn></entry>
            <entry name="WILD"><ip-wildcard>10.0.0.0/0.0.255.255</ip-wildcard></entry>
            <entry name="UNUSED-HOST"><ip-netmask>192.0.2.99</ip-netmask></entry>
            <entry name="NAT-POOL"><ip-netmask>198.51.100.50</ip-netmask></entry>
          </address>
          <address-group>
            <entry name="WEB-SERVERS"><static><member>WEB1</member><member>WEB2</member></static>
              <description>DMZ web tier</description></entry>
            <entry name="ALL-DMZ"><static><member>WEB-SERVERS</member><member>DMZ-NET</member></static></entry>
            <entry name="PARTNERS"><static><member>PARTNER-RANGE</member><member>198.51.100.7</member>
              <member>LOOKUP</member></static></entry>
            <entry name="DYN-WEB"><dynamic><filter>'web' and 'prod'</filter></dynamic></entry>
            <entry name="LOOP-A"><static><member>LOOP-B</member></static></entry>
            <entry name="LOOP-B"><static><member>LOOP-A</member></static></entry>
          </address-group>
          <service>
            <entry name="SVC-HTTPS-ALT"><protocol><tcp><port>8443</port><source-port>1024-65535</source-port>
              </tcp></protocol><description>Alt HTTPS</description></entry>
            <entry name="SVC-DNS"><protocol><udp><port>53</port></udp></protocol></entry>
            <entry name="SVC-WEB"><protocol><tcp><port>80,8080-8090</port><override><no/></override></tcp></protocol></entry>
          </service>
          <service-group>
            <entry name="WEB-PORTS"><members><member>SVC-WEB</member><member>service-https</member></members></entry>
            <entry name="ALL-SVCS"><members><member>WEB-PORTS</member><member>SVC-DNS</member>
              <member>SVC-HTTPS-ALT</member></members></entry>
          </service-group>
          <application-group>
            <entry name="WEB-APPS"><members><member>web-browsing</member><member>ssl</member></members></entry>
          </application-group>
          <application-filter>
            <entry name="LOW-RISK-MAIL"><category><member>collaboration</member></category>
              <subcategory><member>email</member></subcategory><risk><member>1</member></risk></entry>
          </application-filter>
          <external-list>
            <entry name="BAD-IPS"><type><ip><url>https://example.com/bad.txt</url>
              <recurring><daily><at>01</at></daily></recurring></ip></type></entry>
          </external-list>
          <schedule>
            <entry name="BUSINESS-HRS"><schedule-type><recurring><weekly><monday><member>08:00-18:00</member></monday></weekly></recurring></schedule-type></entry>
          </schedule>
          <rulebase>
            <security>
              <rules>
                <entry name="Allow-Partners-Web" uuid="11111111-aaaa-bbbb-cccc-000000000001">
                  <from><member>untrust</member></from><to><member>dmz</member></to>
                  <source><member>PARTNERS</member></source>
                  <destination><member>WEB-SERVERS</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>WEB-APPS</member></application>
                  <service><member>WEB-PORTS</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end><log-setting>to-panorama</log-setting>
                  <profile-setting><profiles><virus><member>default</member></virus>
                    <vulnerability><member>strict</member></vulnerability></profiles></profile-setting>
                  <tag><member>web</member><member>partner</member></tag>
                  <description>Allow partners to web servers
Ticket CHG0001234</description>
                </entry>
                <entry name="Mgmt-SSH">
                  <from><member>trust</member></from><to><member>any</member></to>
                  <source><member>10.9.9.9</member></source>
                  <destination><member>NOSUCH-OBJECT</member></destination>
                  <application><member>ssh</member></application>
                  <service><member>application-default</member></service>
                  <schedule>BUSINESS-HRS</schedule>
                  <action>allow</action><disabled>yes</disabled>
                </entry>
                <entry name="DMZ-Out">
                  <from><member>dmz</member></from><to><member>untrust</member></to>
                  <source><member>ALL-DMZ</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>ALL-SVCS</member></service>
                  <action>allow</action>
                </entry>
                <entry name="Loop-Test">
                  <from><member>any</member></from><to><member>any</member></to>
                  <source><member>LOOP-A</member></source><destination><member>BAD-IPS</member></destination>
                  <application><member>any</member></application><service><member>any</member></service>
                  <action>deny</action><log-start>yes</log-start>
                  <negate-source>no</negate-source>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="Outbound-PAT">
                  <from><member>trust</member></from><to><member>untrust</member></to>
                  <source><member>DMZ-NET</member></source><destination><member>any</member></destination>
                  <service>any</service>
                  <source-translation><dynamic-ip-and-port><translated-address><member>NAT-POOL</member>
                    </translated-address></dynamic-ip-and-port></source-translation>
                  <description>Outbound PAT</description>
                </entry>
              </rules>
            </nat>
            <default-security-rules>
              <rules>
                <entry name="intrazone-default"><action>allow</action><log-end>yes</log-end></entry>
              </rules>
            </default-security-rules>
          </rulebase>
        </entry>
      </vsys>
      <device-group>
        <entry name="DG-Parent">
          <address><entry name="PARENT-NET"><ip-netmask>172.16.0.0/16</ip-netmask></entry></address>
        </entry>
        <entry name="DG-Branch">
          <address><entry name="BR-NET"><ip-netmask>10.50.0.0/16</ip-netmask></entry></address>
          <pre-rulebase><security><rules>
            <entry name="Branch-to-Parent">
              <from><member>any</member></from><to><member>any</member></to>
              <source><member>BR-NET</member></source><destination><member>PARENT-NET</member></destination>
              <application><member>any</member></application><service><member>application-default</member></service>
              <action>allow</action><description>Pre-rule</description>
            </entry></rules></security></pre-rulebase>
          <post-rulebase><security><rules>
            <entry name="Final-Deny">
              <from><member>any</member></from><to><member>any</member></to>
              <source><member>any</member></source><destination><member>any</member></destination>
              <application><member>any</member></application><service><member>any</member></service>
              <action>deny</action>
            </entry></rules></security></post-rulebase>
        </entry>
      </device-group>
    </entry>
  </devices>
  <readonly><devices><entry name="localhost.localdomain"><dg-meta-data><dg-info>
    <entry name="DG-Branch"><parent-dg>DG-Parent</parent-dg></entry>
  </dg-info></dg-meta-data></entry></devices></readonly>
  <shared>
    <address><entry name="SHARED-DNS"><ip-netmask>8.8.8.8</ip-netmask></entry></address>
  </shared>
</config>
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse PAN-OS / Panorama XML config to CSV")
    ap.add_argument("config", nargs="?", help="path to the XML configuration file")
    ap.add_argument("-o", "--outdir", default="output",
                    help="base output folder (default 'output'); each run writes to "
                         "<outdir>/YYYY-MM-DD_HH-MM-SS")
    ap.add_argument("--expand", action="store_true",
                    help="also write rules_expanded.csv (security rules, one row per src x dst x app x service)")
    ap.add_argument("--max-expand", type=int, default=100000, help="max expanded rows per rule")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any reference is unresolved")
    ap.add_argument("--csv-nl-sep", default=" | ",
                    help="string replacing line breaks inside CSV fields (default ' | ')")
    ap.add_argument("--selftest", action="store_true", help="run on the embedded sample config")
    args = ap.parse_args(argv)
    CSV_NL_SEP[0] = args.csv_nl_sep

    try:
        if args.selftest:
            root, args.expand = ET.fromstring(SAMPLE), True
        elif args.config:
            root = load_xml(args.config)
        else:
            ap.error("config file required (or --selftest)")
    except OSError as e:
        print("Cannot read %s: %s" % (args.config, e), file=sys.stderr)
        return 2
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2

    p = PanParser(expand=args.expand, max_expand=args.max_expand)
    try:
        p.parse(root)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2
    run_dir = make_run_dir(args.outdir)
    write_outputs(p, run_dir)
    print_summary(p)
    print("Output written to: %s" % os.path.abspath(run_dir))
    if args.strict and p.unresolved:
        print("STRICT: unresolved references found; see warnings.csv.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())