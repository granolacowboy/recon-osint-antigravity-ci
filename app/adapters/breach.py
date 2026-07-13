import os
from typing import Any, List
from app.adapters.base import ToolAdapter
from app.schemas.base import TargetEntity
from app.schemas.entities import EmailEntity, UsernameEntity
from app.utils.execution import run_cli_command
from app.utils.http import fetch_json

class DeHashedAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, (EmailEntity, UsernameEntity))

    async def run(self, target: TargetEntity) -> Any:
        api_key = os.getenv("DEHASHED_API_KEY", "mock")
        email = os.getenv("DEHASHED_EMAIL", "mock")
        if not api_key or not email:
            return {"entries": []}

        headers = {"Accept": "application/json"}
        url = f"https://api.dehashed.com/search?query={target.value}"
        result = await fetch_json(url, headers=headers)
        return result

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for entry in raw_output.get("entries", []):
            email_val = entry.get("email")
            if email_val:
                ent = EmailEntity(value=email_val)
                ent.metadata["database_name"] = entry.get("database_name")
                ent.metadata["password"] = entry.get("password")
                ent.metadata["hashed_password"] = entry.get("hashed_password")
                results.append(ent)
        return results

class H8mailAdapter(ToolAdapter):
    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, EmailEntity)

    async def run(self, target: TargetEntity) -> Any:
        cmd = ["h8mail", "-t", target.value]
        returncode, stdout, stderr = await run_cli_command(cmd)

        breaches = []
        passwords = []
        if returncode == 0:
            for line in stdout.splitlines():
                if "Breach:" in line:
                    breaches.append(line.split(":")[-1].strip())
                if "Password:" in line:
                    passwords.append(line.split(":")[-1].strip())

        return {
            "results": [
                {
                    "email": target.value,
                    "breaches": breaches,
                    "passwords_found": len(passwords),
                    "cleartext_passwords": passwords,
                }
            ]
        }

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        results = []
        for item in raw_output.get("results", []):
            ent = EmailEntity(value=item["email"])
            ent.metadata["breaches"] = item.get("breaches", [])
            ent.metadata["passwords_found"] = item.get("passwords_found", 0)
            ent.metadata["cleartext_passwords"] = item.get("cleartext_passwords", [])
            results.append(ent)
        return results
