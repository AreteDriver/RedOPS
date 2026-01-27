#!/usr/bin/env python3
"""
Example: Quick Security Scan

This example demonstrates how to run a quick security scan
programmatically using RedOPS.
"""

import sys
from pathlib import Path

# Add src to path if running from examples directory
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redops.pipelines.loader import PipelineLoader
from redops.pipelines.runner import PipelineRunner
from redops.core.config import RedOpsConfig


def quick_scan(target: str, output_dir: str = "./output"):
    """
    Run a quick security scan on a target.

    Args:
        target: Domain or IP to scan
        output_dir: Directory for output files
    """
    print(f"[*] Starting quick scan of: {target}")

    # Load configuration
    config = RedOpsConfig.from_env()
    config.output.output_dir = output_dir

    # Load the reconnaissance pipeline
    pipeline_path = (
        Path(__file__).parent.parent / "config/pipelines/recon_pipeline.json"
    )
    pipeline = PipelineLoader.load(str(pipeline_path))

    print(f"[*] Pipeline: {pipeline.metadata.name}")
    print(f"[*] Steps: {len(pipeline.enabled_steps)}")

    # Create runner and execute
    runner = PipelineRunner(pipeline, config=config)
    ctx = runner.run(target=target)

    # Print results
    print("\n[+] Scan complete!")
    print(f"    Total logs: {len(ctx.logs)}")
    print(f"    Data keys: {list(ctx.data.keys())}")

    # Print any findings
    findings = ctx.data.get("findings", [])
    if findings:
        print(f"\n[!] Found {len(findings)} findings:")
        for f in findings[:5]:
            print(f"    - [{f.get('severity', 'info')}] {f.get('title', 'Unknown')}")

    return ctx


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python quick_scan.py <target>")
        print("Example: python quick_scan.py example.com")
        sys.exit(1)

    target = sys.argv[1]
    quick_scan(target)
