from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import DomainEntity, URLEntity
from app.utils.execution import run_cli_command

class WaybackurlsAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, DomainEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"echo {target.value} | waybackurls"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"urls": stdout.splitlines() if returncode == 0 else []}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        return [URLEntity(value=u) for u in raw_output.get("urls", [])[:10]]

class GauAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, DomainEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"gau {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"urls": stdout.splitlines() if returncode == 0 else []}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        return [URLEntity(value=u) for u in raw_output.get("urls", [])[:10]]
