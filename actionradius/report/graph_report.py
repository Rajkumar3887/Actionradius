from actionradius.models import Finding

def generate_graph_report(findings: list[Finding], output_path: str, target_action: str):
    """
    Generates a Graphviz DOT file mapping the blast radius:
    Action -> Repos -> Secrets
    """
    nodes = set()
    edges = set()
    
    # Define styling
    dot = [
        "digraph BlastRadius {",
        "  rankdir=LR;",
        "  node [fontname=\"Helvetica\"];",
        "  edge [fontname=\"Helvetica\", fontsize=10];",
        "",
        f'  "{target_action}" [shape=octagon, style=filled, fillcolor="#d73a49", fontcolor=white, label="{target_action}\\n(Compromised Action)"];'
    ]
    
    for f in findings:
        repo_name = f"{f.repo.owner}/{f.repo.name}"
        
        # Determine repo color based on severity
        color = "#28a745" # safe / info
        if f.severity == "critical":
            color = "#d73a49"
        elif f.severity == "high":
            color = "#cb2431"
        elif f.severity == "medium":
            color = "#dbab09"
            
        repo_label = f"{repo_name}\\n({f.severity.upper()})"
        if repo_name not in nodes:
            dot.append(f'  "{repo_name}" [shape=box, style=filled, fillcolor="{color}", fontcolor=white, label="{repo_label}"];')
            nodes.add(repo_name)
            
        # Edge from Action to Repo
        pin = f.resolved.uses.ref if f.resolved.uses.ref else "unknown"
        edges.add(f'  "{target_action}" -> "{repo_name}" [label="{pin}", color="#6a737d"];')
        
        # Edges from Repo to Secrets
        for secret in f.secrets.explicit_secrets:
            secret_node = f"secret_{secret}"
            if secret_node not in nodes:
                dot.append(f'  "{secret_node}" [shape=ellipse, style=filled, fillcolor="#ffd33d", label="Secret: {secret}"];')
                nodes.add(secret_node)
            edges.add(f'  "{repo_name}" -> "{secret_node}" [color="#dbab09"];')
            
        if f.secrets.inherits_all:
            if "inherit_all" not in nodes:
                dot.append(f'  "inherit_all" [shape=ellipse, style=filled, fillcolor="#ffd33d", label="Secrets: INHERIT ALL"];')
                nodes.add("inherit_all")
            edges.add(f'  "{repo_name}" -> "inherit_all" [color="#dbab09", style=dashed];')
            
        # Add trigger context if dangerous
        if f.trigger.fork_reachable:
            trigger_node = "trigger_pr_target"
            if trigger_node not in nodes:
                dot.append(f'  "{trigger_node}" [shape=diamond, style=filled, fillcolor="#b392f0", label="Fork-Reachable Trigger\\n(pull_request_target)"];')
                nodes.add(trigger_node)
            edges.add(f'  "{repo_name}" -> "{trigger_node}" [color="#b392f0"];')

    dot.append("")
    dot.extend(list(edges))
    dot.append("}")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(dot))
