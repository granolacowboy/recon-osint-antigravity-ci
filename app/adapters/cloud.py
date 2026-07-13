import json
from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import CompanyEntity, DomainEntity, RepositoryEntity, CloudStorageEntity, UsernameEntity
from app.utils.execution import run_cli_command
from app.utils.http import fetch_json
from app.core.logging import logger

class CloudEnumAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (CompanyEntity, DomainEntity))

    async def run(self, target: TargetEntity) -> Any:
        # Assuming cloud_enum python script is available
        val = target.value.split(".")[0] if isinstance(target, DomainEntity) else target.value
        cmd = f"cloud_enum -k {val} -j report.json"
        returncode, stdout, stderr = await run_cli_command(cmd, timeout=300)

        try:
            with open("report.json", "r") as f:
                data = json.load(f)
            # clean up
            import os
            os.remove("report.json")
            return data
        except Exception:
            return {}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for provider, info in raw_output.items():
            for bucket in info.get("open", []):
                ent = CloudStorageEntity(value=bucket)
                ent.metadata["provider"] = provider
                ent.metadata["access"] = "open"
                results.append(ent)
        return results

class TruffleHogAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, RepositoryEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = f"trufflehog git {target.value} --json"
        returncode, stdout, stderr = await run_cli_command(cmd, timeout=300)

        findings = []
        for line in stdout.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return {"secrets": findings}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for secret in raw_output.get("secrets", []):
            ent = TargetEntity(value=secret.get("DetectorName", "Unknown Secret"))
            ent.metadata["file"] = secret.get("DecoderName", "")
            # Don't store the raw secret to avoid leakage
            ent.metadata["redacted_secret"] = "***"
            results.append(ent)
        return results

class GitReconAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (UsernameEntity, CompanyEntity))

    async def run(self, target: TargetEntity) -> Any:
        # Search Github API for users/orgs
        url = f"https://api.github.com/users/{target.value}/repos"
        # Mock headers or use token if available in env
        headers = {"Accept": "application/vnd.github.v3+json"}
        result = await fetch_json(url, headers=headers)
        return result

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        if isinstance(raw_output, list):
            for repo in raw_output:
                ent = RepositoryEntity(value=repo.get("html_url", ""))
                ent.metadata["description"] = repo.get("description", "")
                ent.metadata["fork"] = repo.get("fork", False)
                results.append(ent)
        return results
