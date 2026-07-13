from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import UsernameEntity, CompanyEntity
from app.utils.execution import run_cli_command

class SocialAnalyzerAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, UsernameEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"social-analyzer --username {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"profiles": ["facebook", "twitter"]} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["social_profiles"] = raw_output.get("profiles", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class OSINTgramAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, UsernameEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"python3 main.py {target.value} info"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"info": "instagram details"} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["osintgram"] = raw_output.get("info", "")
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class CrossLinkedAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, CompanyEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"crosslinked {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"employees": ["John Doe", "Jane Doe"]} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["employees"] = raw_output.get("employees", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
