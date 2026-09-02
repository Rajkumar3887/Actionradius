from actionradius.models import TriggerContext

def extract_trigger_risk(raw_triggers: dict | list | str | bool) -> TriggerContext:
    events = []
    fork_reachable = False
    
    if isinstance(raw_triggers, dict):
        events = list(raw_triggers.keys())
    elif isinstance(raw_triggers, list):
        events = raw_triggers
    elif isinstance(raw_triggers, str):
        events = [raw_triggers]

    fork_reachable_events = {"pull_request_target", "workflow_run", "issue_comment"}
    fork_reachable = bool(set(events).intersection(fork_reachable_events))
    
    privileged_events = {"push", "schedule"}
    
    risk = "low"
    if fork_reachable:
        risk = "high"
    elif set(events).intersection(privileged_events):
        risk = "medium"

    return TriggerContext(
        events=events,
        risk=risk,
        fork_reachable=fork_reachable
    )
