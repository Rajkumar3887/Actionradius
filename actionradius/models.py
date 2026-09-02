import dataclasses
from dataclasses import dataclass, field
from typing import Optional, Literal

# Tri-state compromise classification
CompromiseStatus = Literal["COMPROMISED", "SAFE", "UNKNOWN"]

@dataclass
class RepoRef:
    owner: str
    name: str
    default_branch: str
    is_private: bool

@dataclass
class UsesRef:
    raw: str                          # "tj-actions/changed-files@v45"
    owner: Optional[str]
    repo: Optional[str]
    path: Optional[str]                # subdir action or reusable workflow path
    ref: Optional[str]                           # "v45" | "main" | 40-char sha
    ref_type: Literal["sha", "tag", "branch", "local", "unresolvable", "mutable_ref"]
    is_reusable_workflow: bool

@dataclass
class UsesSite:
    workflow_path: str
    job_id: str
    step_index: Optional[int]          # None = job-level `uses:` (reusable workflow call)
    uses: UsesRef
    depth: int                         # 0 = direct, 1+ = inside a composite/reusable it calls
    source_chain: list[str]            # For tracking recursion path, e.g. ["wf.yml", "reusable.yml"]

@dataclass
class TriggerContext:
    events: list[str]
    risk: Literal["low", "medium", "high"]
    fork_reachable: bool               # pull_request_target / workflow_run / comment-triggered

@dataclass
class PermissionsContext:
    scope: Literal["workflow", "job", "default"]
    contents: str                      # read, write, none
    raw: dict

@dataclass
class SecretsContext:
    inherits_all: bool                 # secrets: inherit
    explicit_secrets: list[str]
    has_real_secrets: bool             # anything beyond default GITHUB_TOKEN

@dataclass
class WorkflowFile:
    repo: RepoRef
    path: str
    triggers: TriggerContext
    permissions: PermissionsContext
    secrets: SecretsContext
    runs_on_self_hosted: bool
    uses_sites: list[UsesSite]
    run_scripts: list[str] = dataclasses.field(default_factory=list)

@dataclass
class ResolvedRef:
    uses: UsesRef
    current_sha: Optional[str]                   # what it resolves to *right now*
    is_mutable: bool
    is_orphan: bool = False

@dataclass
class Finding:
    repo: RepoRef
    uses_site: UsesSite
    resolved: ResolvedRef
    compromise_status: CompromiseStatus           # COMPROMISED / SAFE / UNKNOWN
    historical_exposure: CompromiseStatus          # COMPROMISED if provably was exposed, else UNKNOWN
    pin_type: str                                  # "sha", "tag", "branch", "local", "unresolvable", "mutable_ref"
    trigger: TriggerContext
    permissions: PermissionsContext
    secrets: SecretsContext
    severity: Literal["critical", "high", "medium", "low", "info"]
    score: float
    rationale: str                     # human-readable "why this severity"

    @property
    def is_compromised_version(self) -> bool:
        """Backward-compatible property for existing reports and tests."""
        return self.compromise_status == "COMPROMISED"
