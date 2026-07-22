import json
from typing import List, Dict, Any
from pydantic import BaseModel, Field # Assuming Pydantic for internal data structures/typing hints

# --- Mock Sentinel Internal Types for Context ---
# In a real implementation, these types would be imported from SovereignSentinel or BehavioralBaseline.
class Finding(BaseModel):
    """Represents a single finding found by the Sentinel."""
    hunt_id: str = Field(description="The unique ID of the hunt/rule (e.g., hunt-005).")
    severity: str = Field(enum=['low', 'medium', 'high', 'critical'], description="Severity level.")
    description: str = Field(description="Detailed explanation of the finding.")
    vulnerability_data: Dict[str, Any] = Field(default_factory=dict, description="Additional context/payload data.")
    tags: List[str] = Field(default_factory=list, description="List of tags (e.g., MITRE IDs).")

# --- SARIF Structure Implementation ---

def _map_severity_to_sarif(sentinel_severity: str) -> int:
    """
    Maps internal Sentinel severity strings to SARIF levels (CVSS-like integer representation, 
    or directly using standardized names if the consuming tool supports it).
    For maximal compatibility, we use common descriptive labels.
    """
    levels = {
        'critical': 'error',  # Used for high impact/failure
        'high': 'warning',
        'medium': 'note',     # Standardized approach to semi-severity issues
        'low': 'info',
    }
    return levels.get(sentinel_severity.lower(), 'info')

def create_sarif_result(finding: Finding, location: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Converts a single Sentinel Finding object into a SARIF 2.1 result object.
    
    Args:
        finding: The internal Finding object.
        location: Optional dictionary describing the file/line where the finding occurred 
                  (e.g., {'file': 'src/main.py', 'start_line': 'L42'}).

    Returns:
        A SARIF result dictionary fragment.
    """
    rule_id = finding.hunt_id
    sarif_level = _map_severity_to_sarif(finding.severity)

    # Construct the properties object to hold rich metadata (Tags, CVSS, etc.)
    properties: Dict[str, Any] = {
        "tag-list": ", ".join(set(finding.tags)), # Deduplicate tags for property listing
        "mitre-atlas-id": str(finding.tags).strip('[]'), # Example of specific tag handling
    }

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": sarif_level,
        "message": {"text": finding.description},
        "properties": properties,
        # Add full context/metadata payload here if necessary
    }

    if location:
        result["locations"] = [{
            "source": {"fileURI": location.get('file', 'unknown_source')},
            "region": {
                "startLine": location.get('start_line'),
                "endLine": location.get('end_line')
            }
        }]

    return result


def generate_sarif(findings: List[Finding], run_name: str, file_uri: str) -> Dict[str, Any]:
    """
    Generates a complete SARIF 2.1.0 document from a list of Sentinel findings.

    Args:
        findings: A list of internal Finding objects (results).
        run_name: The name identifying this specific run (e.g., 'baseline-scan-commit-xyz').
        file_uri: The URI/path to the source file being reported on.

    Returns:
        A dictionary representing the complete SARIF document structure.
    """
    if not findings:
        return {
            "version": "2.1.0",
            "runs": []
        }

    results = [create_sarif_result(f) for f in findings]
    
    sarif_document = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-beta.json", # Using a common schema reference
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SovereignSentinel Analyzer",
                "version": "1.0.0",
                "fullyVersion": "1.0.0",
                "rules": [
                    # List all rules/hunts encountered for better tooling integration
                    {"id": f.hunt_id, "name": f"Sentinel Hunt: {f.hunt_id}", "short": {"description": "Checks against a configured security baseline."}}
                    for f in findings
                ]
            }},
            "results": results,
        }]
    }

    return sarif_document


# --- Public Interface for Saving ---

def write_sarif_file(findings: List[Finding], output_path: str, run_name: str = "sentinel-scan"):
    """
    Generates and writes the SARIF JSON document to disk. 
    This function is intended to be called by the main CLI entry point.

    Args:
        findings: The list of findings (e.g., from SovereignSentinel/BehavioralBaseline).
        output_path: The path where the .sarif file should be written.
        run_name: Identifier for this specific run.
    """
    try:
        sarif_data = generate_sarif(findings, run_name, file_uri=output_path)
        with open(output_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"✅ Successfully wrote SARIF report to {output_path}")

    except Exception as e:
        raise RuntimeError(f"Failed to generate SARIF report: {e}")

# Example Usage (Mock):
# mock_findings = [Finding(hunt_id='hunt-001', severity='high', description='Critical flaw detected.', tags=['CVE-2023-999']), ...]
# write_sarif_file(mock_findings, 'results/report.sarif')
