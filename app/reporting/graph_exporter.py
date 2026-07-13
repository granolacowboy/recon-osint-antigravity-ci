import json
import xml.etree.ElementTree as ET
from typing import Dict, Any
from app.core.logging import logger

class GraphExporter:
    """
    Exports the correlated graph to various formats.
    """
    @staticmethod
    def to_json(graph_data: Dict[str, Any], filepath: str):
        with open(filepath, 'w') as f:
            json.dump(graph_data, f, indent=2)
        logger.bind(output_format="json").info("graph_export_completed")

    @staticmethod
    def to_graphml(graph_data: Dict[str, Any], filepath: str):
        """
        Exports to GraphML for visualization in Gephi/yEd/Maltego.
        """
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        graph = ET.SubElement(root, "graph", id="G", edgedefault="directed")

        # Add nodes
        for node in graph_data.get("nodes", []):
            n = ET.SubElement(graph, "node", id=node["id"])
            data = ET.SubElement(n, "data", key="label")
            data.text = node["value"]
            type_data = ET.SubElement(n, "data", key="type")
            type_data.text = node["type"]

        # Add edges
        for idx, edge in enumerate(graph_data.get("edges", [])):
            e = ET.SubElement(graph, "edge", id=f"e{idx}", source=edge["source"], target=edge["target"])
            data = ET.SubElement(e, "data", key="relationship")
            data.text = edge["relationship"]

        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
        logger.bind(output_format="graphml").info("graph_export_completed")
