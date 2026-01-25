#!/usr/bin/env python3
"""
Example: Generate Security Reports

This example demonstrates how to generate various report formats
from scan results using RedOPS.
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def generate_pdf_report(scan_file: str, output_path: str):
    """Generate a PDF report from scan results."""
    from redops.modules.reporting.pdf_report import PDFReportGenerator

    with open(scan_file) as f:
        scan_data = json.load(f)

    print(f"[*] Generating PDF report: {output_path}")

    generator = PDFReportGenerator()
    path = generator.generate(scan_data, output_path)

    print(f"[+] Report saved to: {path}")
    return path


def export_stix(scan_file: str, output_path: str):
    """Export scan results to STIX format."""
    from redops.modules.intel.stix_export import STIXExporter

    with open(scan_file) as f:
        scan_data = json.load(f)

    print(f"[*] Exporting to STIX: {output_path}")

    exporter = STIXExporter()
    bundle = exporter.export(scan_data)

    with open(output_path, "w") as f:
        f.write(bundle.to_json())

    print(f"[+] STIX bundle saved to: {output_path}")
    print(f"    Objects: {len(bundle.objects)}")
    return output_path


def generate_all_reports(scan_file: str, output_dir: str = "./reports"):
    """Generate all report formats from scan results."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    with open(scan_file) as f:
        scan_data = json.load(f)

    target = scan_data.get("target", "unknown")

    print(f"[*] Generating reports for: {target}")

    # PDF Report
    try:
        pdf_path = output_path / f"report_{timestamp}.pdf"
        generate_pdf_report(scan_file, str(pdf_path))
    except ImportError:
        print("[!] PDF generation requires fpdf2: pip install fpdf2")

    # STIX Export
    stix_path = output_path / f"stix_bundle_{timestamp}.json"
    export_stix(scan_file, str(stix_path))

    # JSON summary
    summary_path = output_path / f"summary_{timestamp}.json"
    summary = {
        "target": target,
        "timestamp": scan_data.get("timestamp"),
        "findings_count": len(scan_data.get("findings", [])),
        "report_generated": datetime.now(timezone.utc).isoformat(),
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Summary saved to: {summary_path}")

    print(f"\n[+] All reports generated in: {output_dir}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python generate_reports.py <scan_results.json>")
        print("  python generate_reports.py <scan_results.json> --pdf output.pdf")
        print("  python generate_reports.py <scan_results.json> --stix output.json")
        sys.exit(1)

    scan_file = sys.argv[1]

    if len(sys.argv) >= 4:
        if sys.argv[2] == "--pdf":
            generate_pdf_report(scan_file, sys.argv[3])
        elif sys.argv[2] == "--stix":
            export_stix(scan_file, sys.argv[3])
    else:
        generate_all_reports(scan_file)
