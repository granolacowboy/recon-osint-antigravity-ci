from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import DomainEntity
from app.utils.execution import run_cli_command

class AmassAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, DomainEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"amass enum -d {target.value} -timeout 10"
        returncode, stdout, stderr = await run_cli_command(cmd, timeout=600)

        subdomains = []
        if returncode == 0:
            for line in stdout.splitlines():
                subdomains.append(line.strip())
        return {"subdomains": subdomains}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for sub in raw_output.get("subdomains", []):
            ent = DomainEntity(value=sub)
            ent.metadata["source"] = "amass"
            results.append(ent)
        return results

class AssetfinderAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, DomainEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"assetfinder --subs-only {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)

        subdomains = []
        if returncode == 0:
            for line in stdout.splitlines():
                subdomains.append(line.strip())
        return {"subdomains": subdomains}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for sub in raw_output.get("subdomains", []):
            ent = DomainEntity(value=sub)
            ent.metadata["source"] = "assetfinder"
            results.append(ent)
        return results
