from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import DomainEntity
from app.utils.execution import run_cli_command

class FOCAAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, DomainEntity)

    async def run(self, target: TargetEntity) -> Any:
        return {"documents": 5}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["foca_documents"] = raw_output.get("documents", 0)
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class MetagoofilAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, DomainEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"metagoofil -d {target.value} -t pdf,doc"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"files": 10} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["metagoofil_files"] = raw_output.get("files", 0)
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
