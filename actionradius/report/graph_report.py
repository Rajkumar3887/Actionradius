from actionradius.models import Finding


def _dot_escape(value: str) -> str:
    """
    Escape a value for safe interpolation inside a double-quoted DOT
    string/ID. Repo/owner names are constrained by GitHub's own naming
    rules and secret/ref names by GitHub Actions' identifier syntax, so in
    practice these rarely contain special characters — but escaping here is
    cheap, doesn't change output for well-formed input, and prevents a
    stray `"` or backslash from breaking out of the quoted string (which
    would corrupt the graph or, worst case, let a crafted name inject extra
    DOT statements into the generated file).
    """
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def generate_graph_report(findings: list[Finding], output_path: str, target_action: str):
    """
    Generates a Graphviz DOT file mapping the blast radius:
    Action -> Repos -> Secrets
    """
    nodes = set()
    edges = set()

    target_action_esc = _dot_escape(target_action)

    # Define styling
    dot = [
        "digraph BlastRadius {",
        "  rankdir=LR;",
        "  node [fontname=\"Helvetica\"];",
        "  edge [fontname=\"Helvetica\", fontsize=10];",
        "",
        f'  "{target_action_esc}" [shape=octagon, style=filled, fillcolor="#d73a49", fontcolor=white, label="{target_action_esc}\\n(Compromised Action)"];'
    ]

    for f in findings:
        repo_name = f"{f.repo.owner}/{f.repo.name}"
        repo_name_esc = _dot_escape(repo_name)

        # Determine repo color based on severity
        color = "#28a745" # safe / info
        if f.severity == "critical":
            color = "#d73a49"
        elif f.severity == "high":
            color = "#cb2431"
        elif f.severity == "medium":
            color = "#dbab09"

        repo_label = f"{repo_name_esc}\\n({f.severity.upper()})"
        if repo_name not in nodes:
            dot.append(f'  "{repo_name_esc}" [shape=box, style=filled, fillcolor="{color}", fontcolor=white, label="{repo_label}"];')
            nodes.add(repo_name)

        # Edge from Action to Repo
        pin = f.resolved.uses.ref if f.resolved.uses.ref else "unknown"
        pin_esc = _dot_escape(pin)
        edges.add(f'  "{target_action_esc}" -> "{repo_name_esc}" [label="{pin_esc}", color="#6a737d"];')

        # Edges from Repo to Secrets
        for secret in f.secrets.explicit_secrets:
            secret_esc = _dot_escape(secret)
            secret_node = f"secret_{secret}"
            secret_node_esc = f"secret_{secret_esc}"
            if secret_node not in nodes:
                dot.append(f'  "{secret_node_esc}" [shape=ellipse, style=filled, fillcolor="#ffd33d", label="Secret: {secret_esc}"];')
                nodes.add(secret_node)
            edges.add(f'  "{repo_name_esc}" -> "{secret_node_esc}" [color="#dbab09"];')

        if f.secrets.inherits_all:
            if "inherit_all" not in nodes:
                dot.append(f'  "inherit_all" [shape=ellipse, style=filled, fillcolor="#ffd33d", label="Secrets: INHERIT ALL"];')
                nodes.add("inherit_all")
            edges.add(f'  "{repo_name_esc}" -> "inherit_all" [color="#dbab09", style=dashed];')

        # Add trigger context if dangerous
        if f.trigger.fork_reachable:
            trigger_node = "trigger_pr_target"
            if trigger_node not in nodes:
                dot.append(f'  "{trigger_node}" [shape=diamond, style=filled, fillcolor="#b392f0", label="Fork-Reachable Trigger\\n(pull_request_target)"];')
                nodes.add(trigger_node)
            edges.add(f'  "{repo_name_esc}" -> "{trigger_node}" [color="#b392f0"];')

    dot.append("")
    dot.extend(list(edges))
    dot.append("}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(dot))
