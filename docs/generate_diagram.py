import base64
import zlib
import urllib.request
import os

mermaid_code = """
graph TD
    A[CLI] --> B[Inventory Engine]
    B -->|"GET /orgs/X/repos"| C[GitHub API]
    B -->|"GET /trees/main?recursive=1"| C
    B --> D[AST Parser]
    D -->|"Extracts uses:, env:, secrets:, on:"| E[Context Modeler]
    E --> F[Ref Resolver]
    F -->|"GET /git/ref/tags/v1"| C
    F -->|"GET /compare/HEAD...SHA"| C
    F --> G[Scoring Engine]
    G --> H[Reports: JSON / HTML / SARIF / Graphviz]
"""

# Compress and encode for Kroki
compressed = zlib.compress(mermaid_code.encode('utf-8'), 9)
encoded = base64.urlsafe_b64encode(compressed).decode('utf-8')

url = f"https://kroki.io/mermaid/png/{encoded}"

os.makedirs("docs", exist_ok=True)
output_path = "docs/architecture.png"

try:
    print(f"Downloading architecture diagram from {url}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response, open(output_path, 'wb') as out_file:
        out_file.write(response.read())
    print(f"Saved to {output_path}")
except Exception as e:
    print(f"Error: {e}")
