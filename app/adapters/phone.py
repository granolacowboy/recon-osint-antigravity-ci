from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import PhoneEntity
from app.utils.execution import run_cli_command

class PhoneInfogaAdapter(ToolAdapter):
    """
    Adapter for the PhoneInfoga phone number intelligence tool.
    """
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, PhoneEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"phoneinfoga scan -n {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)

        carrier = ""
        country = ""
        line_type = ""
        if returncode == 0:
            for line in stdout.splitlines():
                if "Carrier" in line:
                    carrier = line.split(":")[-1].strip()
                if "Country" in line:
                    country = line.split(":")[-1].strip()
                if "Line type" in line:
                    line_type = line.split(":")[-1].strip()

        return {
            "valid": returncode == 0,
            "carrier": carrier,
            "line_type": line_type,
            "country": country
        }

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        if raw_output.get("valid"):
            ent = PhoneEntity(value=self._current_target.value if hasattr(self, '_current_target') else "")
            ent.metadata["carrier"] = raw_output.get("carrier")
            ent.metadata["line_type"] = raw_output.get("line_type")
            ent.metadata["country"] = raw_output.get("country")
            results.append(ent)
        return results

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
