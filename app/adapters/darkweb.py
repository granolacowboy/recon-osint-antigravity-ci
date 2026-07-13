from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import DomainEntity, URLEntity, UsernameEntity
from app.utils.execution import run_cli_command

class TorBotAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, DomainEntity) and target.value.endswith(".onion")

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"torbot -u http://{target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"scanned": returncode == 0}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["torbot_scanned"] = raw_output.get("scanned", False)
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class OnionSearchAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (UsernameEntity, DomainEntity))

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"onionsearch {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        urls = []
        if returncode == 0:
            for line in stdout.splitlines():
                if ".onion" in line:
                    urls.append(line.strip())
        return {"onion_urls": urls}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        return [URLEntity(value=u) for u in raw_output.get("onion_urls", [])]

class DarkdumpAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, UsernameEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"python3 darkdump.py --query {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"found": "true" in stdout.lower()}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["darkdump_found"] = raw_output.get("found", False)
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
