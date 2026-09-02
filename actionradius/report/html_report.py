import os
from jinja2 import Environment, FileSystemLoader
from actionradius.models import Finding

def generate_html_report(findings: list[Finding], output_path: str, target: str):
    # Sort findings by score descending
    findings = sorted(findings, key=lambda f: f.score, reverse=True)
    
    # Split safe and exposed
    safe_findings = [f for f in findings if not f.is_compromised_version]
    exposed_findings = [f for f in findings if f.is_compromised_version]

    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")))
    template = env.get_template("report.html.j2")
    
    html_content = template.render(
        target=target,
        exposed_findings=exposed_findings,
        safe_findings=safe_findings
    )
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
