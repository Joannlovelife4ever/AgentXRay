#!/usr/bin/env python3
"""Build an Agent-System Evidence Graph (ASEG) from an OSWorld trajectory and Linux audit log.

The output is a dependency-free node-link JSON graph.  It distinguishes:
  * agent actions (what the model attempted),
  * audit events (what the kernel observed),
  * processes, files, network endpoints, and permission effects, and
  * evidence links (temporal/semantic correlation, not automatic causation).

Example:
  python aseg_builder.py --agent better_log.json --audit audit.log --output aseg.json

By default, noisy sendto/recvfrom events and file accesses outside /home/user are
suppressed. Use --include-packet-io and --all-files to retain them.
"""

from __future__ import annotations

import argparse
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import socket
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator


AUDIT_ID_RE = re.compile(r"audit\((?P<sec>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
TYPE_RE = re.compile(r"^type=(\w+)")
PAIR_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\"(?:\\.|[^\"])*\"|'[^']*'|[^\s\x1d]+)")
SCREENSHOT_TS_RE = re.compile(r"(?P<date>\d{8})@(?P<time>\d{6})")

FILE_SYSCALLS = {
    "open", "openat", "creat", "mkdir", "mkdirat", "rename", "renameat",
    "renameat2", "unlink", "unlinkat", "rmdir", "link", "linkat", "symlink",
    "symlinkat", "truncate", "chmod", "fchmod", "fchmodat", "chown", "fchown",
    "fchownat", "lchown", "setxattr", "lsetxattr", "fsetxattr", "removexattr",
}
NETWORK_SYSCALLS = {"connect", "accept", "accept4"}
PACKET_SYSCALLS = {"sendto", "recvfrom", "sendmsg", "recvmsg"}
PERMISSION_SYSCALLS = {
    "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown",
    "setuid", "setreuid", "setresuid", "setgid", "setregid", "setresgid",
    "setfsuid", "setfsgid", "capset", "setxattr", "lsetxattr", "fsetxattr",
}
WRITE_LIKE = {
    "creat", "mkdir", "mkdirat", "rename", "renameat", "renameat2", "unlink",
    "unlinkat", "rmdir", "link", "linkat", "symlink", "symlinkat", "truncate",
    "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown",
    "setxattr", "lsetxattr", "fsetxattr", "removexattr",
}
STOPWORDS = {
    "import", "time", "sleep", "click", "doubleclick", "pyautogui", "press",
    "hotkey", "typewrite", "focus", "button", "window", "selected", "file",
    "open", "close", "next", "step", "ensure", "correct", "command", "with",
    "from", "this", "that", "into", "then", "and", "the", "for", "run",
    "home", "user", "usr", "bin",
    "time.sleep", "python", "python3", "local", "lib", "site-packages",
}


def clean_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def parse_pairs(text: str) -> dict[str, str]:
    return {m.group("key"): clean_value(m.group("value")) for m in PAIR_RE.finditer(text)}


def stable_id(prefix: str, *parts: object) -> str:
    raw = "\x1f".join(str(p) for p in parts).encode("utf-8", "replace")
    return f"{prefix}:{hashlib.sha256(raw).hexdigest()[:16]}"


def iso_utc(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def screenshot_epoch(name: str | None) -> float | None:
    match = SCREENSHOT_TS_RE.search(name or "")
    if not match:
        return None
    stamp = match.group("date") + match.group("time")
    return dt.datetime.strptime(stamp, "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc).timestamp()


def decode_hex_text(value: str | None, nul: str = " ") -> str | None:
    if not value or len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", value):
        return value
    try:
        return bytes.fromhex(value).decode("utf-8", "replace").replace("\x00", nul).strip()
    except (ValueError, UnicodeDecodeError):
        return value


def decode_sockaddr(raw: str | None) -> dict[str, Any]:
    if not raw or not re.fullmatch(r"[0-9a-fA-F]+", raw):
        return {"raw": raw, "family": "unknown"}
    try:
        data = bytes.fromhex(raw)
        if len(data) < 2:
            raise ValueError
        family = int.from_bytes(data[:2], "little")
        if family == socket.AF_INET and len(data) >= 8:
            return {"family": "inet", "address": socket.inet_ntop(socket.AF_INET, data[4:8]),
                    "port": int.from_bytes(data[2:4], "big"), "raw": raw}
        if family == socket.AF_INET6 and len(data) >= 24:
            return {"family": "inet6", "address": socket.inet_ntop(socket.AF_INET6, data[8:24]),
                    "port": int.from_bytes(data[2:4], "big"), "raw": raw}
        if family == socket.AF_UNIX:
            path = data[2:].rstrip(b"\x00").decode("utf-8", "replace")
            return {"family": "unix", "path": path, "raw": raw}
        return {"family": str(family), "raw": raw}
    except (ValueError, OSError, binascii.Error):
        return {"raw": raw, "family": "unknown"}


@dataclass
class AuditEvent:
    serial: int
    timestamp: float
    records: list[dict[str, Any]] = field(default_factory=list)

    def first(self, record_type: str) -> dict[str, Any] | None:
        return next((r for r in self.records if r["type"] == record_type), None)

    def all(self, record_type: str) -> list[dict[str, Any]]:
        return [r for r in self.records if r["type"] == record_type]


def iter_audit_events(path: Path) -> Iterator[AuditEvent]:
    """Stream audit records and group them by boot-local audit serial."""
    groups: dict[int, AuditEvent] = {}
    order: list[int] = []
    # Audit records for an event are normally contiguous. A small buffer avoids
    # holding a multi-GB log in memory while tolerating short interleaving.
    max_open = 256
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            ident = AUDIT_ID_RE.search(line)
            typ = TYPE_RE.search(line)
            if not ident or not typ:
                continue
            serial = int(ident.group("serial"))
            event = groups.get(serial)
            if event is None:
                event = groups[serial] = AuditEvent(serial, float(ident.group("sec")))
                order.append(serial)
            fields = parse_pairs(line)
            event.records.append({"type": typ.group(1), "fields": fields,
                                  "raw": line.rstrip("\n"), "line": line_no})
            if len(order) > max_open:
                old = order.pop(0)
                yield groups.pop(old)
    for serial in order:
        yield groups[serial]


def infer_action_times(steps: list[dict[str, Any]]) -> list[float | None]:
    times = [screenshot_epoch(step.get("screenshot_file")) for step in steps]
    deltas = [b - a for a, b in zip(times, times[1:]) if a is not None and b is not None and 0 < b - a < 300]
    typical = statistics.median(deltas) if deltas else 20.0
    for i, value in enumerate(times):
        if value is None:
            future = next((t for t in times[i + 1:] if t is not None), None)
            past = next((t for t in reversed(times[:i]) if t is not None), None)
            if future is not None:
                times[i] = future - typical
            elif past is not None:
                times[i] = past + typical
    return times


def action_text(step: dict[str, Any]) -> str:
    actions = step.get("actions") or []
    if isinstance(actions, str):
        actions = [actions]
    return "\n".join(str(x) for x in actions)


def action_terms(text: str) -> set[str]:
    terms = set(re.findall(r"[A-Za-z0-9_.~/-]{3,}", text.lower()))
    expanded = set(terms)
    for term in terms:
        expanded.update(x for x in re.split(r"[/_.~-]+", term) if len(x) >= 3)
        if "/" in term:
            expanded.add(os.path.basename(term))
    return {t for t in expanded if t not in STOPWORDS and not re.fullmatch(r"\d+(?:\.\d+)?", t)}


def event_summary(event: AuditEvent) -> dict[str, Any] | None:
    syscall_rec = event.first("SYSCALL")
    exec_rec = event.first("EXECVE")
    sockaddr_rec = event.first("SOCKADDR")
    paths = [r["fields"].get("name") for r in event.all("PATH") if r["fields"].get("name")]
    cwd_rec = event.first("CWD")
    cwd = cwd_rec["fields"].get("cwd") if cwd_rec else None
    if syscall_rec:
        sf = syscall_rec["fields"]
        syscall = sf.get("SYSCALL") or sf.get("syscall")
        success = sf.get("success")
        pid = int(sf["pid"]) if sf.get("pid", "").isdigit() else None
        ppid = int(sf["ppid"]) if sf.get("ppid", "").isdigit() else None
        exe, comm = sf.get("exe"), sf.get("comm")
        uid, euid = sf.get("uid"), sf.get("euid")
        key = sf.get("key")
    else:
        syscall = success = pid = ppid = exe = comm = uid = euid = key = None
    argv: list[str] = []
    if exec_rec:
        ef = exec_rec["fields"]
        argc = int(ef.get("argc", "0")) if ef.get("argc", "").isdigit() else 0
        argv = [ef.get(f"a{i}", "") for i in range(argc)]
    proctitle_rec = event.first("PROCTITLE")
    proctitle = decode_hex_text(proctitle_rec["fields"].get("proctitle"), " ") if proctitle_rec else None
    endpoint = decode_sockaddr(sockaddr_rec["fields"].get("saddr")) if sockaddr_rec else None
    if not syscall and not exec_rec:
        return None
    return {
        "serial": event.serial, "timestamp": event.timestamp, "syscall": syscall,
        "success": success, "pid": pid, "ppid": ppid, "exe": exe, "comm": comm,
        "uid": uid, "euid": euid, "key": key, "argv": argv, "proctitle": proctitle,
        "cwd": cwd, "paths": paths, "endpoint": endpoint,
        "source_lines": [r["line"] for r in event.records],
        "record_types": [r["type"] for r in event.records],
    }


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def node(self, node_id: str, node_type: str, **attrs: Any) -> str:
        clean = {k: v for k, v in attrs.items() if v is not None}
        existing = self.nodes.setdefault(node_id, {"id": node_id, "type": node_type})
        existing.update(clean)
        return node_id

    def edge(self, source: str, target: str, relation: str, *, discriminator: str = "", **attrs: Any) -> None:
        key = (source, target, relation, discriminator)
        value = {"source": source, "target": target, "relation": relation}
        value.update({k: v for k, v in attrs.items() if v is not None})
        self.edges[key] = value

    def export(self, metadata: dict[str, Any]) -> dict[str, Any]:
        counts = Counter(n["type"] for n in self.nodes.values())
        metadata = dict(metadata, node_counts=dict(sorted(counts.items())), edge_count=len(self.edges))
        return {"schema": "aseg-node-link-v1", "metadata": metadata,
                "nodes": list(self.nodes.values()), "edges": list(self.edges.values())}


def path_is_relevant(path: str, all_files: bool, home_prefix: str) -> bool:
    return all_files or path.startswith(home_prefix)


def event_terms(summary: dict[str, Any]) -> set[str]:
    values: list[str] = []
    values.extend(summary.get("paths") or [])
    values.extend(summary.get("argv") or [])
    values.extend([summary.get("exe") or "", summary.get("comm") or "", summary.get("proctitle") or ""])
    return action_terms(" ".join(values))


def classify_file_relation(syscall_name: str | None) -> str:
    if syscall_name in {"unlink", "unlinkat", "rmdir"}:
        return "deletes"
    if syscall_name in {"rename", "renameat", "renameat2"}:
        return "renames"
    if syscall_name in {"mkdir", "mkdirat", "creat", "link", "linkat", "symlink", "symlinkat"}:
        return "creates"
    if syscall_name in PERMISSION_SYSCALLS:
        return "changes_permission_on"
    if syscall_name in WRITE_LIKE:
        return "modifies"
    return "accesses"


def build_aseg(agent_path: Path, audit_path: Path, *, all_files: bool = False,
               include_packet_io: bool = False, home_prefix: str = "/home/user",
               clock_offset: float = 0.0, window_slack: float = 2.0,
               full_audit: bool = False) -> dict[str, Any]:
    agent = json.loads(agent_path.read_text(encoding="utf-8"))
    steps = agent.get("steps") or []
    times = infer_action_times(steps)
    graph = Graph()
    action_ids: list[str] = []
    action_term_sets: list[set[str]] = []
    windows: list[tuple[float, float, str, int]] = []

    task = agent.get("task") or {}
    task_id = stable_id("task", task.get("instruction", ""), agent_path.name)
    graph.node(task_id, "task", instruction=task.get("instruction"), injection=task.get("injection"),
               parameters=agent.get("params"))
    known_times = [t for t in times if t is not None]
    final_end = (max(known_times) + 30.0) if known_times else float("inf")
    for i, (step, timestamp) in enumerate(zip(steps, times)):
        text = action_text(step)
        action_id = f"action:{i}"
        action_ids.append(action_id)
        action_term_sets.append(action_terms(text))
        graph.node(action_id, "agent_action", step=i, timestamp=iso_utc(timestamp), epoch=timestamp,
                   screenshot_file=step.get("screenshot_file"), code=text,
                   response=step.get("response"), observation_kind="a11y_tree+screenshot")
        graph.edge(task_id, action_id, "has_action", order=i)
        if i:
            graph.edge(action_ids[i - 1], action_id, "next_action")
        if timestamp is not None:
            next_known = next((t for t in times[i + 1:] if t is not None), final_end)
            windows.append((timestamp - window_slack, next_known + window_slack, action_id, i))

    stats = Counter()
    summaries: list[dict[str, Any]] = []
    capture_start = min(known_times) - 30.0 if known_times else float("-inf")
    capture_end = max(known_times) + 30.0 if known_times else float("inf")
    for audit_event in iter_audit_events(audit_path):
        summary = event_summary(audit_event)
        if not summary:
            continue
        syscall_name = summary["syscall"]
        is_exec = bool(summary["argv"]) or syscall_name in {"execve", "execveat"}
        relevant_paths = [p for p in summary["paths"] if path_is_relevant(p, all_files, home_prefix)]
        is_network = syscall_name in NETWORK_SYSCALLS or (include_packet_io and syscall_name in PACKET_SYSCALLS)
        is_permission = syscall_name in PERMISSION_SYSCALLS
        if not (is_exec or relevant_paths or is_network or is_permission):
            stats["filtered_events"] += 1
            continue
        summary["paths"] = relevant_paths
        summary["timestamp"] += clock_offset
        if not full_audit and not (capture_start <= summary["timestamp"] <= capture_end):
            stats["outside_trajectory"] += 1
            continue
        summaries.append(summary)

    # Establish process nodes first so parent edges do not depend on event order.
    process_info: dict[int, dict[str, Any]] = {}
    for summary in summaries:
        pid = summary.get("pid")
        if pid is None:
            continue
        info = process_info.setdefault(pid, {"pid": pid, "first_seen": summary["timestamp"]})
        info["first_seen"] = min(info["first_seen"], summary["timestamp"])
        for key in ("ppid", "exe", "comm", "uid", "euid"):
            if summary.get(key) is not None:
                info[key] = summary[key]
    for pid, info in process_info.items():
        graph.node(f"process:{pid}", "process", **info, first_seen_iso=iso_utc(info["first_seen"]))
    for pid, info in process_info.items():
        ppid = info.get("ppid")
        if ppid in process_info and ppid != pid:
            graph.edge(f"process:{ppid}", f"process:{pid}", "parent_of")

    for summary in summaries:
        serial = summary["serial"]
        event_id = f"audit:{serial}"
        timestamp = summary["timestamp"]
        syscall_name = summary.get("syscall")
        graph.node(event_id, "system_event", timestamp=iso_utc(timestamp), epoch=timestamp,
                   serial=serial, syscall=syscall_name, success=summary.get("success"),
                   audit_key=summary.get("key"), record_types=summary.get("record_types"),
                   source_lines=summary.get("source_lines"), cwd=summary.get("cwd"))
        pid = summary.get("pid")
        if pid is not None:
            graph.edge(f"process:{pid}", event_id, "performed")

        if summary.get("argv"):
            command_id = stable_id("command", pid, serial, *summary["argv"])
            graph.node(command_id, "process_effect", effect="execution", argv=summary["argv"],
                       command=" ".join(shlex.quote(x) for x in summary["argv"]),
                       executable=summary.get("exe"), success=summary.get("success"))
            graph.edge(event_id, command_id, "records_effect")

        for ordinal, path in enumerate(summary.get("paths") or []):
            file_id = stable_id("file", path)
            graph.node(file_id, "file", path=path, basename=os.path.basename(path))
            graph.edge(event_id, file_id, classify_file_relation(syscall_name), discriminator=str(ordinal))

        endpoint = summary.get("endpoint")
        if endpoint:
            identity = endpoint.get("path") or f"{endpoint.get('address')}:{endpoint.get('port')}"
            endpoint_id = stable_id("endpoint", endpoint.get("family"), identity)
            graph.node(endpoint_id, "network_endpoint", **endpoint)
            graph.edge(event_id, endpoint_id, "network_effect", operation=syscall_name,
                       success=summary.get("success"))

        if syscall_name in PERMISSION_SYSCALLS:
            effect_id = stable_id("permission", serial, syscall_name)
            graph.node(effect_id, "permission_effect", operation=syscall_name,
                       uid=summary.get("uid"), effective_uid=summary.get("euid"),
                       success=summary.get("success"), paths=summary.get("paths"))
            graph.edge(event_id, effect_id, "records_effect")

        candidates = [w for w in windows if w[0] <= timestamp <= w[1]]
        terms = event_terms(summary)
        # Boundary slack can make adjacent windows overlap. Assign an event to
        # the most recent applicable action so evidence is not double counted.
        selected = max(candidates, key=lambda w: (times[w[3]] or float("-inf"))) if candidates else None
        for start, end, action_id, action_index in ([selected] if selected else []):
            overlap = sorted(action_term_sets[action_index] & terms)
            # 0.55 means temporal support only. Semantic overlap raises—but does
            # not convert—the link into a causal assertion.
            confidence = min(0.95, 0.55 + 0.10 * min(len(overlap), 4))
            graph.edge(action_id, event_id, "correlated_with", discriminator=str(serial),
                       confidence=round(confidence, 2), methods=["time_window"] + (["semantic_overlap"] if overlap else []),
                       matched_terms=overlap, delta_seconds=round(timestamp - (times[action_index] or timestamp), 3))
            stats["evidence_links"] += 1
        stats["retained_events"] += 1

    metadata = {
        "agent_source": agent_path.name, "audit_source": audit_path.name,
        "generated_at": iso_utc(dt.datetime.now(dt.timezone.utc).timestamp()),
        "time_basis": "UTC inferred from screenshot filenames and audit epoch timestamps",
        "clock_offset_seconds": clock_offset, "window_slack_seconds": window_slack,
        "home_prefix": home_prefix, "all_files": all_files,
        "include_packet_io": include_packet_io, "full_audit": full_audit,
        "trajectory_bounds": [iso_utc(capture_start), iso_utc(capture_end)],
        "statistics": dict(stats),
        "interpretation_warning": "correlated_with edges are evidence associations, not proof of causation",
    }
    return graph.export(metadata)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agent", type=Path, required=True, help="AI-level OSWorld trajectory JSON")
    parser.add_argument("--audit", type=Path, required=True, help="Linux audit log (raw or enriched)")
    parser.add_argument("--output", type=Path, required=True, help="Output node-link JSON")
    parser.add_argument("--all-files", action="store_true", help="Keep file events outside --home-prefix")
    parser.add_argument("--home-prefix", default="/home/user", help="Default relevant file-tree prefix")
    parser.add_argument("--include-packet-io", action="store_true", help="Keep noisy send/receive syscall events")
    parser.add_argument("--full-audit", action="store_true", help="Do not restrict events to the trajectory time span")
    parser.add_argument("--clock-offset", type=float, default=0.0, help="Seconds added to audit timestamps")
    parser.add_argument("--window-slack", type=float, default=2.0, help="Evidence-window boundary slack in seconds")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation; use 0 for compact output")
    args = parser.parse_args()
    graph = build_aseg(args.agent, args.audit, all_files=args.all_files,
                       include_packet_io=args.include_packet_io, home_prefix=args.home_prefix,
                       clock_offset=args.clock_offset, window_slack=args.window_slack,
                       full_audit=args.full_audit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(graph, indent=args.indent or None, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "nodes": len(graph["nodes"]),
                      "edges": len(graph["edges"]), "counts": graph["metadata"]["node_counts"]}, indent=2))


if __name__ == "__main__":
    main()
