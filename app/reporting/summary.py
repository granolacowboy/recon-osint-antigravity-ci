from typing import Dict, Any
from app.core.logging import logger

class SummaryReport:
    """
    Generates a Markdown executive summary of the findings.
    """
    @staticmethod
    def generate_markdown(graph_data: Dict[str, Any], filepath: str):
        nodes = graph_data.get("nodes", [])

        # Aggregate statistics
        stats = {}
        for node in nodes:
            t = node["type"]
            stats[t] = stats.get(t, 0) + 1

        lines = [
            "# RECON OSINT Executive Summary\n",
            "## Discovered Entities\n"
        ]

        for k, v in stats.items():
            lines.append(f"- **{k}**: {v}")

        lines.append("\n## High Value Findings\n")
        for node in nodes:
            if node["type"] in ["VulnerabilityEntity", "CVEEntity", "CloudStorageEntity"]:
                lines.append(f"- [{node['type']}] {node['value']}")

        with open(filepath, 'w') as f:
            f.write("\n".join(lines))
        logger.bind(output_format="markdown").info("summary_export_completed")
