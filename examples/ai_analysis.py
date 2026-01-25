#!/usr/bin/env python3
"""
Example: AI-Powered Security Analysis

This example demonstrates how to use RedOPS AI features
to analyze scan results and get intelligent recommendations.

Requires: ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redops.modules.ai_assistant import AIAssistant


def analyze_scan_results(scan_file: str):
    """
    Analyze scan results using AI.

    Args:
        scan_file: Path to JSON file with scan results
    """
    # Load scan data
    with open(scan_file) as f:
        scan_data = json.load(f)

    print("[*] Initializing AI Assistant...")

    try:
        assistant = AIAssistant()
        print(f"    Provider: {assistant.provider}")
        print(f"    Model: {assistant.model}")
    except ValueError as e:
        print(f"[!] Error: {e}")
        print("    Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable")
        sys.exit(1)

    # Analyze findings
    print("\n[*] Analyzing findings...")
    analysis = assistant.analyze_findings(scan_data)
    print("\n--- AI Analysis ---")
    print(analysis)

    # Get recommendations
    print("\n[*] Generating recommendations...")
    recommendations = assistant.suggest_remediations(scan_data)
    print("\n--- Recommendations ---")
    print(recommendations)

    # Generate executive summary
    print("\n[*] Creating executive summary...")
    summary = assistant.summarize(scan_data)
    print("\n--- Executive Summary ---")
    print(summary)


def explain_concept(query: str):
    """
    Get AI explanation of a security concept.

    Args:
        query: Security question or concept
    """
    print(f"[*] Question: {query}")

    try:
        assistant = AIAssistant()
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    explanation = assistant.explain(query)
    print("\n--- Explanation ---")
    print(explanation)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ai_analysis.py <scan_results.json>")
        print("  python ai_analysis.py --explain 'What is SQL injection?'")
        sys.exit(1)

    if sys.argv[1] == "--explain":
        query = " ".join(sys.argv[2:])
        explain_concept(query)
    else:
        analyze_scan_results(sys.argv[1])
