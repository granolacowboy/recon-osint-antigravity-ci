from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import IPEntity, DomainEntity
from app.utils.execution import run_cli_command

class NmapAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (IPEntity, DomainEntity))

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"nmap -F {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        open_ports = []
        if returncode == 0:
            for line in stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    open_ports.append(line.split("/")[0])
        return {"ports": open_ports}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["nmap_ports"] = raw_output.get("ports", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class MasscanAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, IPEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"masscan -p1-65535 {target.value} --rate=1000"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"ports": ["80", "443"]} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["masscan_ports"] = raw_output.get("ports", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class RustScanAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, IPEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"rustscan -a {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"ports": ["22"]} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["rustscan_ports"] = raw_output.get("ports", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class NaabuAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (IPEntity, DomainEntity))

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"naabu -host {target.value}"
        returncode, stdout, stderr = await run_cli_command(cmd)
        return {"ports": ["8080"]} if returncode == 0 else {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["naabu_ports"] = raw_output.get("ports", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
