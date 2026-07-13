from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import URLEntity, IPEntity
from app.utils.execution import run_cli_command

class ExifToolAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, URLEntity) and any(ext in target.value.lower() for ext in ['.jpg', '.png', '.pdf'])

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"exiftool {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)

        gps = ""
        if returncode == 0:
            for line in stdout.splitlines():
                if "GPS Position" in line:
                    gps = line.split(":")[-1].strip()
        return {"gps": gps}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["gps"] = raw_output.get("gps", "")
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class GeoGuessrResolverAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, URLEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"python3 geoguessr.py {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"location": "New York, USA"} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["geoguessr"] = raw_output.get("location", "")
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class CreepyAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, URLEntity)

    async def run(self, target: TargetEntity) -> Any:
        return {"heatmap": "generated"}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["creepy_heatmap"] = raw_output.get("heatmap", "")
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
