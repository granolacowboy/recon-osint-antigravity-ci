import json
from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import DomainEntity, IPEntity, VulnerabilityEntity, CVEEntity
from app.utils.execution import run_cli_command
from app.utils.http import fetch_json
from app.core.logging import logger

class NucleiAdapter(ToolAdapter):
    """
    Runs nuclei with passive templates.
    """
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (DomainEntity, IPEntity))

    async def run(self, target: TargetEntity) -> Any:
        # Run in JSON output mode, only passive tags to avoid active scanning
        cmd = f"nuclei -u {target.value} -tags passive -json -silent"
        returncode, stdout, stderr = await run_cli_command(cmd, timeout=300)

        findings = []
        if returncode == 0 and stdout:
            for line in stdout.splitlines():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return {"findings": findings}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for finding in raw_output.get("findings", []):
            info = finding.get("info", {})
            vuln_name = info.get("name", "Unknown Vulnerability")
            ent = VulnerabilityEntity(value=vuln_name)
            ent.metadata["severity"] = info.get("severity", "info")
            ent.metadata["matched_at"] = finding.get("matched-at", "")

            # Extract CVEs if present
            cves = info.get("classification", {}).get("cve-id", [])
            for cve in cves:
                cve_ent = CVEEntity(value=cve.upper())
                cve_ent.metadata["source"] = "nuclei"
                cve_ent.metadata["related_vuln"] = vuln_name
                results.append(cve_ent)

            results.append(ent)
        return results

class SearchSploitAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        # Needs specific service/software names, usually gathered in metadata
        return isinstance(target, IPEntity) and "ports" in target.metadata

    async def run(self, target: TargetEntity) -> Any:
        # Searchsploit needs specific terms, we'll dummy search based on port for this mock implementation
        results = []
        for port in target.metadata.get("ports", []):
            if port == "80" or port == "443":
                cmd = "searchsploit apache -j"
                returncode, stdout, stderr = await run_cli_command(cmd, timeout=30)
                if returncode == 0:
                    try:
                        results.append(json.loads(stdout))
                    except json.JSONDecodeError:
                        pass
        return {"exploits": results}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for exploit_data in raw_output.get("exploits", []):
            for res in exploit_data.get("RESULTS_EXPLOIT", [])[:3]: # Limit to top 3
                ent = VulnerabilityEntity(value=res.get("Title", "Unknown Exploit"))
                ent.metadata["edb_id"] = res.get("EDB-ID")
                ent.metadata["type"] = res.get("Type")
                results.append(ent)
        return results

class VulnersAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, CVEEntity)

    async def run(self, target: TargetEntity) -> Any:
        url = f"https://vulners.com/api/v3/search/id/?id={target.value}"
        result = await fetch_json(url)
        return result

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        data = raw_output.get("data", {}).get("documents", {})
        for doc_id, doc_info in data.items():
            ent = VulnerabilityEntity(value=doc_info.get("title", doc_id))
            ent.metadata["cvss"] = doc_info.get("cvss", {}).get("score")
            ent.metadata["description"] = doc_info.get("description", "")
            results.append(ent)
        return results
