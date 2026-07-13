from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import DomainEntity, IPEntity, URLEntity, CompanyEntity
from app.utils.http import fetch_json

class MISPAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (DomainEntity, IPEntity, URLEntity))

    async def run(self, target: TargetEntity) -> Any:
        return {"events": [{"info": "Malware C2", "attribute_count": 5}]}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["misp_events"] = [e["info"] for e in raw_output.get("events", [])]
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class OpenCTIAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (DomainEntity, IPEntity))

    async def run(self, target: TargetEntity) -> Any:
        return {"reports": ["APT29 Campaign"]}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["opencti_reports"] = raw_output.get("reports", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)

class YetiAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (DomainEntity, IPEntity))

    async def run(self, target: TargetEntity) -> Any:
        return {"tags": ["malware", "phishing"]}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        ent = self._current_target.model_copy()
        ent.metadata["yeti_tags"] = raw_output.get("tags", [])
        return [ent]

    async def execute(self, target: TargetEntity) -> List[TargetEntity]:
        self._current_target = target
        return await super().execute(target)
