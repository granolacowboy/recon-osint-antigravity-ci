import json
from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import UsernameEntity, URLEntity
from app.utils.execution import run_cli_command

class SherlockAdapter(ToolAdapter):
    """
    Adapter for the Sherlock username enumeration tool.
    """
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, UsernameEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = ["sherlock", target.value, "--print-found", "--timeout", "10"]
        returncode, stdout, stderr = await run_cli_command(cmd)

        found_urls = []
        if returncode == 0:
            for line in stdout.splitlines():
                if line.startswith("http"):
                    found_urls.append(line)
        return {"urls": found_urls}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for url in raw_output.get("urls", []):
            ent = URLEntity(value=url)
            ent.metadata["source"] = "sherlock"
            results.append(ent)
        return results

class BlackbirdAdapter(ToolAdapter):
    """
    Adapter for the Blackbird username enumeration tool.
    """
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, UsernameEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = ["blackbird", "-u", target.value]
        returncode, stdout, stderr = await run_cli_command(cmd)

        found_sites = []
        if returncode == 0:
            for line in stdout.splitlines():
                if "FOUND" in line and "NOT FOUND" not in line and "http" in line:
                    parts = line.split("http")
                    if len(parts) > 1:
                        found_sites.append("http" + parts[1].strip())
        return {"urls": found_sites}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for url in raw_output.get("urls", []):
            ent = URLEntity(value=url)
            ent.metadata["source"] = "blackbird"
            results.append(ent)
        return results
