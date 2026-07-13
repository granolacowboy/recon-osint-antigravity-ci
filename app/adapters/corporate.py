from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import CompanyEntity, DomainEntity, IPEntity
from app.utils.execution import run_cli_command

class SpiderFootAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (CompanyEntity, DomainEntity, IPEntity))

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"sf.py -s {target.value} -q"
        returncode, stdout, stderr = await run_cli_command(cmd, timeout=300)

        entities_found = []
        if returncode == 0:
            for line in stdout.splitlines():
                if "Domain Name" in line:
                    entities_found.append({"type": "domain", "val": line.split(":")[-1].strip()})
        return {"results": entities_found}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for item in raw_output.get("results", []):
            if item["type"] == "domain":
                ent = DomainEntity(value=item["val"])
                ent.metadata["source"] = "spiderfoot"
                results.append(ent)
        return results
