import json
from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import EmailEntity, DomainEntity
from app.utils.execution import run_cli_command

class MosintAdapter(ToolAdapter):
    """
    Adapter for the Mosint email reconnaissance tool.
    """
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, EmailEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"mosint {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)

        domain = target.value.split("@")[-1] if "@" in target.value else ""
        breaches = []
        if returncode == 0:
            for line in stdout.splitlines():
                if "breach" in line.lower() or "leak" in line.lower():
                    breaches.append("Unknown Breach")
        return {
            "domain": domain,
            "breaches": breaches
        }

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        if raw_output.get("domain"):
            ent = DomainEntity(value=raw_output["domain"])
            ent.metadata["source"] = "mosint"
            ent.metadata["breaches"] = raw_output.get("breaches", [])
            results.append(ent)
        return results

class TheHarvesterAdapter(ToolAdapter):
    """
    Adapter for theHarvester email/domain reconnaissance tool.
    """
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, EmailEntity) or isinstance(target, DomainEntity)

    async def run(self, target: TargetEntity) -> Any:
        target_val = target.value.split("@")[-1] if isinstance(target, EmailEntity) else target.value
        cmd = f"theHarvester -d {target_val} -b all"
        returncode, stdout, stderr = await run_cli_command(cmd)

        found_emails = []
        if returncode == 0:
            for line in stdout.splitlines():
                if "@" in line and target_val in line:
                    found_emails.append(line.strip())
        return {"emails": found_emails}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for email in raw_output.get("emails", []):
            ent = EmailEntity(value=email)
            results.append(ent)
        return results
