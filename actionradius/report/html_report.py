import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from actionradius.models import Finding

def generate_html_report(findings: list[Finding], output_path: str, target: str):
    # Sort findings by score descending
    findings = sorted(findings, key=lambda f: f.score, reverse=True)

    # Split into three categories
    compromised_findings = [f for f in findings if f.compromise_status == "COMPROMISED"]
    unknown_findings = [f for f in findings if f.compromise_status == "UNKNOWN"]
    safe_findings = [f for f in findings if f.compromise_status == "SAFE"]

    # autoescape is required here: several rendered fields (the raw `uses:`
    # string, workflow paths, repo owner/name, rationale text) originate from
    # YAML content in third-party/attacker-controlled repositories. Without
    # HTML-escaping, a workflow crafted with e.g. `uses: <script>...` or a
    # repo named to include markup would execute when a triager opens the
    # generated report in a browser (stored XSS via the scan target itself).
    env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")

    html_content = template.render(
        target=target,
        compromised_findings=compromised_findings,
        unknown_findings=unknown_findings,
        safe_findings=safe_findings,
        # Backward compat aliases
        exposed_findings=compromised_findings,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
