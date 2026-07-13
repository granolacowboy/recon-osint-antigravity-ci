from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import IPEntity, DomainEntity
from app.schemas.outcomes import (
    AdapterNoResultsError,
    AdapterUnavailableError,
    HTTPStatusAdapterError,
)
from app.utils.http import fetch_json

class ShodanAdapter(ToolAdapter):
    version = "shodan-host-api-v1"

    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, IPEntity)

    async def run(self, target: TargetEntity) -> Any:
        api_key = self.config.SHODAN_API_KEY
        if not api_key:
            raise RuntimeError("Shodan adapter ran without configured credentials")
        url = f"https://api.shodan.io/shodan/host/{target.value}"
        try:
            return await fetch_json(url, params={"key": api_key}, retries=1)
        except HTTPStatusAdapterError as exc:
            if exc.status_code == 404:
                raise AdapterNoResultsError(
                    "provider returned no host record", code="provider_not_found"
                ) from None
            if exc.status_code in {401, 403}:
                raise AdapterUnavailableError(
                    "provider rejected configured credentials",
                    code="provider_authentication_failed",
                ) from None
            raise

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for host in raw_output.get("hostnames", []):
            ent = DomainEntity(value=host)
            ent.metadata["ports"] = raw_output.get("ports", [])
            ent.metadata["org"] = raw_output.get("org", "")
            results.append(ent)
        return results

class CensysAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, IPEntity)

    async def run(self, target: TargetEntity) -> Any:
        return {"services": [{"port": 80}, {"port": 443}]}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        if raw_output.get("services"):
            ent = IPEntity(value=self._current_target.value)
            ent.metadata["ports"] = [s.get("port") for s in raw_output["services"]]
            results.append(ent)
        return results

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
