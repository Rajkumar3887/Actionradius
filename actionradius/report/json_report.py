import json
import dataclasses
from actionradius.models import Finding

class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)

def generate_json_report(findings: list[Finding], output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, cls=EnhancedJSONEncoder, indent=2)
