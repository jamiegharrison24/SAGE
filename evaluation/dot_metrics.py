"""
Parses rendered attack graph `.dot` files into raw counts and structural metrics.

Deliberately knows nothing about SAGE: it takes a path to a GraphViz digraph and
returns counts. The paper claims this evaluation module is reusable, and a
`.dot` reader that does not import the pipeline actually is.

Why a hand-written parser rather than pydot/networkx: adding a dependency was
out of scope (`requirements.txt` is fixed), and the graphs SAGE emits use a
dialect that trips naive readers -- node names carry **literal newlines** inside
their quotes, e.g.

    "HOST DISCOVERY
    ms-wbt-server" -> "SERVICE DISCOVERY
    ff-ice" [ label="..." ]

so splitting on '\\n' mid-name invents nodes that do not exist. `_logical_lines`
splits on newlines only outside quotes, which reassembles the real statements.

Every derived metric is returned next to the raw counts it came from, and each
carries its formula as a string (see `FORMULAS`). Formula strings are not
decoration: the paper source that defines these metrics is not available, so the
recorded formula is the only audit trail for how a baseline number was computed.
"""
import glob
import os
import re
from collections import Counter

# Recorded verbatim into every result record. Where the paper is ambiguous or
# silent, the choice made here is stated explicitly rather than left implicit.
FORMULAS = {
    'branching_factor':
        'edges_total / nodes  '
        '(paper definition; edge basis = multi-edges PRESERVED, self-loops included. '
        'NOTE: this is not the conventional mean out-degree)',
    'simplicity':
        'nodes / edges_total  '
        '(reciprocal of branching_factor; same edge basis. '
        'Included only for comparability with Nadeem et al.)',
    'path_linearity':
        'longest_path_edges / edges_total  '
        '(longest path measured in EDGES traversed, over the same preserved edge basis)',
    'reachability_density':
        '|{(u,v) : u != v, v reachable from u}| / (nodes * (nodes - 1))  '
        '(HEADLINE density. The paper gives no formula, defining density only by intent -- it '
        '"captures how easily an attacker can traverse the network". This is the literal '
        'reading: the fraction of ordered state pairs the attacker can actually get between, '
        'following edges any distance. Same normalisation as edge density, so it stays in '
        '[0,1] and remains comparable across graphs. Preferred over edge density because edge '
        'density is confounded by graph size -- measured across the 104 CPTC-2017 baseline '
        'AGs, corr(nodes, edge_density) = -0.79 versus corr(nodes, reachability_density) = '
        '+0.17 -- and because the paper already defines branching_factor = edges/nodes, which '
        'an edges-per-node density largely duplicates. Null when nodes < 2.)',
    'density':
        'edges_simple_no_loops / (nodes * (nodes - 1))  '
        '(textbook directed simple-graph density, retained for comparability with the wider '
        'graph literature but NOT the headline density -- see reachability_density for why. '
        'Multi-edges COLLAPSED and self-loops EXCLUDED from the numerator, because V*(V-1) '
        'counts ordered distinct pairs and neither is representable in it; leaving them in '
        'can push density above 1. Null when nodes < 2.)',
}

# How the two edge bases are built from the raw edge list. Both are always
# recorded, so any ratio above can be re-derived from a stored record without
# re-running the pipeline.
EDGE_BASES = {
    'edges_total': 'every edge line, multi-edges preserved, self-loops included',
    'edges_simple': 'distinct (tail, head) pairs, self-loops included',
    'edges_simple_no_loops': 'distinct (tail, head) pairs where tail != head',
}

MULTIEDGE_POLICY = 'both_recorded'

# Guard for the exact longest-path search. AGs are not DAGs -- SAGE emits
# self-loops and can emit cycles -- so the exact search is exponential in the
# worst case. A node-count cap is a poor guard because cost is driven by density,
# not size: the observed CPTC-2017 graphs are sparse enough that all 104 solve
# exactly in ~0.15s at 50 nodes. So we budget the actual search instead, and fall
# back to the DAG-condensation bound only when a graph genuinely blows up.
# The method is recorded per graph either way, so a baseline number is never
# silently compared against an approximation later.
EXACT_LONGEST_PATH_MAX_STEPS = 2_000_000


def _logical_lines(text):
    """
    Splits `.dot` source into statements, treating newlines inside double-quoted
        strings as part of the string rather than as separators.

    @param text: the full text of a .dot file
    @return: a list of logical lines (statements), with blank ones dropped
    """
    lines, current, in_quote, escaped = [], [], False, False
    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == '\\':
            current.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            continue
        if ch == '\n' and not in_quote:
            lines.append(''.join(current))
            current = []
            continue
        current.append(ch)
    lines.append(''.join(current))
    return [ln for ln in lines if ln.strip()]


def _split_attributes(statement):
    """
    Splits a statement into the part before its attribute list and the attribute
        list itself, ignoring brackets that occur inside quotes.

    Attribute values are where non-node quoted strings live (`label="..."`,
    `tooltip="..."`, `rankdir="BT"`), so node names are only ever read from the
    returned prefix.

    @param statement: a single logical line
    @return: (prefix, attribute_text)
    """
    in_quote, escaped, depth = False, False, 0
    for i, ch in enumerate(statement):
        if escaped:
            escaped = False
            continue
        if ch == '\\':
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        if ch == '[':
            if depth == 0:
                return statement[:i], statement[i:]
            depth += 1
        elif ch == ']':
            depth -= 1
    return statement, ''


def _quoted_names(prefix):
    """
    Extracts quoted node names from a statement prefix.

    Skips any quoted string directly preceded by '=', which is an attribute
    value that leaked outside a bracket list (`rankdir="BT";`) rather than a node.

    @param prefix: the part of a statement before its attribute list
    @return: the list of node names, in order of appearance
    """
    names, i, n = [], 0, len(prefix)
    while i < n:
        if prefix[i] != '"':
            i += 1
            continue
        # Walk back over whitespace to see whether this is an attribute value
        j = i - 1
        while j >= 0 and prefix[j] in ' \t':
            j -= 1
        is_value = j >= 0 and prefix[j] == '='

        i += 1
        start, escaped = i, False
        while i < n:
            if escaped:
                escaped = False
            elif prefix[i] == '\\':
                escaped = True
            elif prefix[i] == '"':
                break
            i += 1
        if not is_value:
            names.append(prefix[start:i])
        i += 1
    return names


def _has_edge_op(prefix):
    """
    Reports whether a statement prefix contains a '->' edge operator outside quotes.

    @param prefix: the part of a statement before its attribute list
    @return: True if this statement declares an edge
    """
    in_quote, escaped = False, False
    for i, ch in enumerate(prefix):
        if escaped:
            escaped = False
            continue
        if ch == '\\':
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if not in_quote and ch == '-' and prefix[i + 1:i + 2] == '>':
            return True
    return False


def parse_dot(text):
    """
    Parses `.dot` source into its node set and edge list.

    @param text: the full text of a .dot file
    @return: (nodes, edges) where nodes is a set of names and edges is a list of
        (tail, head) pairs with multi-edges preserved, in file order
    """
    nodes, edges = set(), []
    for statement in _logical_lines(text):
        prefix, _ = _split_attributes(statement)
        names = _quoted_names(prefix)
        if not names:
            continue
        if _has_edge_op(prefix):
            # An edge chain "a" -> "b" -> "c" contributes each consecutive pair.
            for tail, head in zip(names, names[1:]):
                edges.append((tail, head))
            nodes.update(names)
        else:
            # A node definition, or a rank group listing existing nodes; both
            # only ever mention real nodes, so the union is correct either way.
            nodes.update(names)
    return nodes, edges


def _longest_path_edges(nodes, simple_edges):
    """
    Finds the number of edges on the longest simple path (no repeated node).

    AGs are not DAGs, so this is the NP-hard longest-path problem. We attempt an
    exact search under a step budget (`EXACT_LONGEST_PATH_MAX_STEPS`) and fall
    back to the DAG-condensation bound if the budget is exhausted, reporting
    which was used so a later comparison never mistakes an approximation for an
    exact figure.

    @param nodes: the set of node names
    @param simple_edges: a set of distinct (tail, head) pairs
    @return: (longest_path_in_edges, method)
    """
    adjacency = {node: set() for node in nodes}
    for tail, head in simple_edges:
        if tail != head:  # A self-loop can never extend a simple path
            adjacency[tail].add(head)

    if not nodes:
        return 0, 'empty'

    best, steps, exhausted = 0, 0, False

    def walk(node, visited, depth):
        nonlocal best, steps, exhausted
        if exhausted:
            return
        steps += 1
        if steps > EXACT_LONGEST_PATH_MAX_STEPS:
            exhausted = True
            return
        best = max(best, depth)
        for nxt in adjacency[node]:
            if nxt not in visited:
                visited.add(nxt)
                walk(nxt, visited, depth + 1)
                visited.remove(nxt)

    # A deep chain can exceed the interpreter's recursion limit before the step
    # budget bites; treat that the same as exhausting the budget.
    try:
        for start in nodes:
            walk(start, {start}, 0)
            if exhausted:
                break
    except RecursionError:
        exhausted = True

    if not exhausted:
        return best, 'exact_dfs'
    return _condensation_longest_path(nodes, adjacency), 'condensation_bound'


def _reachability_density(nodes, simple_edges):
    """
    Computes the fraction of ordered node pairs the attacker can traverse between.

    Counts pairs reachable over paths of any length, not just direct edges, which
    is what the paper's "how easily an attacker can traverse the network" actually
    describes. Self-loops are irrelevant (a node reaching itself is not a
    traversal) and are excluded, as is the diagonal, matching the V*(V-1)
    denominator.

    @param nodes: the set of node names
    @param simple_edges: a set of distinct (tail, head) pairs
    @return: the reachability density in [0, 1], or None when nodes < 2
    """
    if len(nodes) < 2:
        return None

    adjacency = {node: set() for node in nodes}
    for tail, head in simple_edges:
        if tail != head:
            adjacency[tail].add(head)

    reachable_pairs = 0
    for start in nodes:
        seen, stack = set(), [start]
        while stack:  # Iterative, so a deep graph cannot blow the stack
            for nxt in adjacency[stack.pop()]:
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        seen.discard(start)  # Reaching yourself via a cycle is not a traversal
        reachable_pairs += len(seen)

    return reachable_pairs / (len(nodes) * (len(nodes) - 1))


def _condensation_longest_path(nodes, adjacency):
    """
    Bounds the longest path by collapsing strongly connected components and
        taking the longest path through the resulting DAG, counting each
        component as one step.

    @param nodes: the set of node names
    @param adjacency: node -> set of successors, self-loops already removed
    @return: an upper-bound path length in edges
    """
    index, low, on_stack, stack, order = {}, {}, set(), [], []
    component = {}
    counter = [0]

    for root in nodes:  # Iterative Tarjan; recursion would risk a stack overflow
        if root in index:
            continue
        work = [(root, iter(adjacency[root]))]
        index[root] = low[root] = counter[0]
        counter[0] += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, successors = work[-1]
            advanced = False
            for nxt in successors:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter[0]
                    counter[0] += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(adjacency[nxt])))
                    advanced = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                members = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component[member] = len(order)
                    members.append(member)
                    if member == node:
                        break
                order.append(members)

    dag = {i: set() for i in range(len(order))}
    for node, successors in adjacency.items():
        for nxt in successors:
            if component[node] != component[nxt]:
                dag[component[node]].add(component[nxt])

    memo = {}

    def depth(comp):
        if comp in memo:
            return memo[comp]
        memo[comp] = 0  # Guards against re-entry; the DAG itself is acyclic
        memo[comp] = max([depth(nxt) + 1 for nxt in dag[comp]], default=0)
        return memo[comp]

    return max([depth(comp) for comp in dag], default=0)


def graph_metrics(text, name=None, with_sets=False):
    """
    Computes the raw counts and structural metrics for a single attack graph.

    @param text: the full text of a .dot file
    @param name: an optional identifier to carry into the record
    @param with_sets: also return the node and edge sets under '_nodes'/'_edges',
        for callers computing cross-graph unions or Jaccard distances. Keys are
        underscore-prefixed and stripped before serialisation, since embedding
        every node name would bloat the stored record enormously.
    @return: a dict of raw counts and derived metrics
    """
    nodes, edges = parse_dot(text)
    simple_edges = set(edges)
    self_loops = sum(1 for tail, head in edges if tail == head)
    simple_no_loops = {(t, h) for t, h in simple_edges if t != h}

    n_nodes = len(nodes)
    n_edges = len(edges)
    longest_edges, method = _longest_path_edges(nodes, simple_edges)

    ordered_pairs = n_nodes * (n_nodes - 1)
    record = {
        'name': name,
        'nodes': n_nodes,
        'edges_total': n_edges,
        'edges_simple': len(simple_edges),
        'edges_simple_no_loops': len(simple_no_loops),
        'self_loops': self_loops,
        'parallel_edges': n_edges - len(simple_edges),
        'longest_path_edges': longest_edges,
        'longest_path_nodes': longest_edges + 1 if n_nodes else 0,
        'longest_path_method': method,
        'branching_factor': (n_edges / n_nodes) if n_nodes else None,
        'simplicity': (n_nodes / n_edges) if n_edges else None,
        'path_linearity': (longest_edges / n_edges) if n_edges else None,
        'density': (len(simple_no_loops) / ordered_pairs) if ordered_pairs else None,
        'reachability_density': _reachability_density(nodes, simple_edges),
    }
    if with_sets:
        record['_nodes'], record['_edges'] = nodes, edges
    return record


# `<exp>.txt-attack-graph-for-victim-<victim>-<objective>.dot`
_AG_FILENAME = re.compile(r'^(?P<prefix>.*)-attack-graph-for-victim-'
                          r'(?P<victim>.+?)-(?P<objective>[^-]+)$')


def parse_ag_filename(path):
    """
    Recovers the (victim, objective) identity of an attack graph from its filename.

    The AG directory holds a `.dot`, a `.png` and an `.svg` per graph, so counting
    files triples the graph count. Identity must come from (victim, objective).

    @param path: the path to an attack graph file
    @return: (victim, objective), or (None, None) if the name does not match
    """
    stem = os.path.splitext(os.path.basename(path))[0]
    match = _AG_FILENAME.match(stem)
    if not match:
        return None, None
    return match.group('victim'), match.group('objective')


def directory_metrics(ag_directory):
    """
    Computes per-graph metrics for every `.dot` attack graph in a directory, plus
        the dataset-level aggregate.

    @param ag_directory: the `<experiment>AGs` directory produced by a run
    @return: a dict with 'per_graph', 'aggregate' and 'distribution' sections
    @raise FileNotFoundError: if the directory holds no .dot files, which almost
        always means the run was made without --keep-files
    """
    dot_files = sorted(glob.glob(os.path.join(ag_directory, '*.dot')))
    if not dot_files:
        raise FileNotFoundError(
            'No .dot files in {!r}. Attack graph .dot files are deleted unless SAGE is '
            'run with --keep-files, and every metric here is derived from them.'
            .format(ag_directory))

    per_graph, victims, objectives = [], set(), set()
    all_nodes, all_edges = set(), set()
    for path in dot_files:
        victim, objective = parse_ag_filename(path)
        with open(path, 'r', encoding='utf-8') as handle:
            record = graph_metrics(handle.read(), name=os.path.basename(path), with_sets=True)
        record['victim'], record['objective'] = victim, objective
        # Union across graphs, so a node reached in several AGs counts once.
        all_nodes.update(record.pop('_nodes'))
        all_edges.update(record.pop('_edges'))
        per_graph.append(record)
        victims.add(victim)
        objectives.add(objective)

    totals = Counter()
    for record in per_graph:
        for key in ('nodes', 'edges_total', 'edges_simple', 'edges_simple_no_loops',
                    'self_loops', 'parallel_edges'):
            totals[key] += record[key]

    # Distinct (victim, objective) pairs -- the real graph count, not the file count.
    n_graphs = len({(r['victim'], r['objective']) for r in per_graph})
    aggregate = {
        'n_attack_graphs': n_graphs,
        'n_dot_files': len(dot_files),
        'n_victims': len(victims),
        'n_objectives': len(objectives),
        # 'total_*' sums per-graph counts, so a node appearing in three AGs counts
        # three times; 'unique_*' is the union across the directory. Both are kept
        # because the compression ratios are defined against different ones.
        'total_nodes': totals['nodes'],
        'total_edges': totals['edges_total'],
        'unique_nodes': len(all_nodes),
        'unique_edges': len(all_edges),
        'self_loops': totals['self_loops'],
        'parallel_edges': totals['parallel_edges'],
        'multiedges': MULTIEDGE_POLICY,
        'longest_path_methods': dict(Counter(r['longest_path_method'] for r in per_graph)),
    }

    return {
        'per_graph': per_graph,
        'aggregate': aggregate,
        'distribution': {key: _distribution([r[key] for r in per_graph])
                         for key in ('nodes', 'edges_total', 'longest_path_edges',
                                     'branching_factor', 'simplicity', 'path_linearity',
                                     'reachability_density', 'density')},
        'formulas': FORMULAS,
        'edge_bases': EDGE_BASES,
    }


def _distribution(values):
    """
    Summarises a list of per-graph values, ignoring graphs where the metric was
        undefined (a null, e.g. density on a single-node graph).

    @param values: the per-graph values
    @return: a dict with n, min, median, mean and max
    """
    present = sorted(v for v in values if v is not None)
    if not present:
        return {'n': 0, 'min': None, 'median': None, 'mean': None, 'max': None}
    midpoint = len(present) // 2
    median = (present[midpoint] if len(present) % 2
              else (present[midpoint - 1] + present[midpoint]) / 2)
    return {
        'n': len(present),
        'min': present[0],
        'median': median,
        'mean': sum(present) / len(present),
        'max': present[-1],
    }
