from __future__ import annotations

try:
    from st2common.runners.base_action import Action
except ModuleNotFoundError:
    class Action:  # type: ignore[no-redef]
        pass


class PlanRemediationAction(Action):
    def run(
        self,
        action_id: str,
        target_id: str = "selected-context",
        reason: str = "portal dry-run",
    ) -> dict[str, object]:
        return {
            "dry_run": True,
            "execution_blocked": True,
            "human_review_required": True,
            "action_id": action_id,
            "target_id": target_id,
            "reason": reason,
        }
