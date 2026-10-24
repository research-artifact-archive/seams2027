"""Exact fairness checks on a supplied finite, fixed-controller graph.

TRUST BOUNDARY: This module does not extract controllers or verify game safety,
input coverage, deterministic responses, memory identity, or start-state mapping.
Each state ID must already identify a complete game/controller-memory product
state. PASS certifies only the two graph properties below on that supplied graph.

JSON schema (all five keys required; no additional keys):
  states: nonempty list of unique nonempty string IDs
  edges: list of unique [source_id, target_id] pairs
  starts: nonempty list of unique state IDs
  env_justice, sys_justice: lists of state-ID sets, represented as unique-ID lists
Empty justice lists and empty individual justice sets are permitted. Every ID
must belong to states. IDs, edges, and output are ordered lexicographically.

CLI: python3 graph_fairness.py graph.json
Exit codes: 0 PASS, 1 FAIL, 2 INVALID (schema or file/JSON error).
"""

from collections import deque
import json
import sys


class GraphValidationError(ValueError):
    """The supplied graph does not satisfy the explicit input schema."""


def _ids(value, name, known=None, nonempty=False):
    if not isinstance(value, list):
        raise GraphValidationError(f"{name} must be a list")
    if any(not isinstance(x, str) or not x for x in value):
        raise GraphValidationError(f"{name} must contain nonempty string IDs")
    if len(set(value)) != len(value):
        raise GraphValidationError(f"{name} contains duplicate IDs")
    if nonempty and not value:
        raise GraphValidationError(f"{name} must not be empty")
    if known is not None and not set(value) <= known:
        raise GraphValidationError(f"{name} contains unknown IDs")
    return set(value)


def _validate(data):
    keys = {"states", "edges", "starts", "env_justice", "sys_justice"}
    if not isinstance(data, dict) or set(data) != keys:
        raise GraphValidationError("graph requires exactly: " + ", ".join(sorted(keys)))
    states = _ids(data["states"], "states", nonempty=True)
    starts = _ids(data["starts"], "starts", states, nonempty=True)
    if not isinstance(data["edges"], list):
        raise GraphValidationError("edges must be a list")
    edges = set()
    for index, edge in enumerate(data["edges"]):
        if not isinstance(edge, list) or len(edge) != 2:
            raise GraphValidationError(f"edges[{index}] must be a two-ID list")
        if any(not isinstance(x, str) or x not in states for x in edge):
            raise GraphValidationError(f"edges[{index}] contains an unknown or invalid ID")
        pair = tuple(edge)
        if pair in edges:
            raise GraphValidationError("edges contains a duplicate pair")
        edges.add(pair)
    justices = []
    for name in ("env_justice", "sys_justice"):
        if not isinstance(data[name], list):
            raise GraphValidationError(f"{name} must be a list of ID sets")
        justices.append([
            _ids(label, f"{name}[{index}]", states)
            for index, label in enumerate(data[name])
        ])
    adjacency = {v: [] for v in states}
    reverse = {v: [] for v in states}
    for source, target in sorted(edges):
        adjacency[source].append(target)
        reverse[target].append(source)
    return states, starts, edges, adjacency, reverse, justices


def _reachable(seeds, adjacency, allowed=None):
    """BFS with deterministic predecessor choices, without recursion."""
    parent = {v: None for v in sorted(seeds)}
    queue = deque(sorted(seeds))
    while queue:
        vertex = queue.popleft()
        for successor in adjacency[vertex]:
            if (allowed is None or successor in allowed) and successor not in parent:
                parent[successor] = vertex
                queue.append(successor)
    return parent


def _path(vertex, parent):
    result = []
    while vertex is not None:
        result.append(vertex)
        vertex = parent[vertex]
    return list(reversed(result))


def _sccs(vertices, adjacency, reverse):
    """Iterative Kosaraju, restricted to the induced graph on vertices."""
    seen, finish = set(), []
    for root in sorted(vertices):
        if root in seen:
            continue
        seen.add(root)
        stack = [(root, 0)]
        while stack:
            vertex, index = stack[-1]
            successors = adjacency[vertex]
            if index == len(successors):
                stack.pop()
                finish.append(vertex)
                continue
            successor = successors[index]
            stack[-1] = (vertex, index + 1)
            if successor in vertices and successor not in seen:
                seen.add(successor)
                stack.append((successor, 0))
    assigned, components = set(), []
    for root in reversed(finish):
        if root in assigned:
            continue
        assigned.add(root)
        stack, members = [root], []
        while stack:
            vertex = stack.pop()
            members.append(vertex)
            for predecessor in reversed(reverse[vertex]):
                if predecessor in vertices and predecessor not in assigned:
                    assigned.add(predecessor)
                    stack.append(predecessor)
        components.append(sorted(members))
    return sorted(components)


def _describe(component, adjacency, env_justice):
    members = set(component)
    cyclic = len(component) > 1 or component[0] in adjacency[component[0]]
    hits = [bool(members & label) for label in env_justice]
    return {"states": component, "cyclic": cyclic, "env_justice_hits": hits,
            "accepting": cyclic and all(hits)}


def analyze_graph(data):
    """Return exact graph-property results; reject malformed input explicitly."""
    states, starts, edges, adjacency, reverse, justices = _validate(data)
    env_justice, sys_justice = justices
    parent = _reachable(starts, adjacency)
    reachable = set(parent)
    components = [_describe(c, adjacency, env_justice)
                  for c in _sccs(reachable, adjacency, reverse)]
    fair_vertices = {v for c in components if c["accepting"] for v in c["states"]}
    can_reach_fair = set(_reachable(fair_vertices, reverse, reachable))
    bad = sorted(reachable - can_reach_fair)
    counterexamples = []
    for index, guarantee in enumerate(sys_justice):
        for component in _sccs(reachable - guarantee, adjacency, reverse):
            description = _describe(component, adjacency, env_justice)
            if description["accepting"]:
                counterexamples.append({
                    "sys_justice_index": index,
                    "scc": description,
                    "full_graph_prefix": _path(component[0], parent),
                })
    return {
        "status": "PASS" if not bad and not counterexamples else "FAIL",
        "scope": "Graph fairness only; extraction, safety, coverage, response determinism, "
                 "memory identity, and start mapping are external obligations.",
        "state_count": len(states), "edge_count": len(edges),
        "starts": sorted(starts), "reachable": sorted(reachable),
        "reachable_sccs": components,
        "nonconflicting": {
            "pass": not bad, "can_reach_accepting_scc": sorted(can_reach_fair),
            "failing_states": bad,
            "first_failing_prefix": _path(bad[0], parent) if bad else None,
        },
        "strict_liveness": {"pass": not counterexamples,
                            "counterexamples": counterexamples},
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(json.dumps({"status": "INVALID", "error": "provide one JSON graph path"},
                         sort_keys=True))
        return 2
    try:
        with open(argv[0], encoding="utf-8") as handle:
            result = analyze_graph(json.load(handle))
    except (OSError, UnicodeError, json.JSONDecodeError, GraphValidationError) as error:
        print(json.dumps({"status": "INVALID", "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
