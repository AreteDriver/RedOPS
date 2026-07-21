"""
RedOps - Advanced modular AI-assisted recon, forensics, and exposure-analysis framework.

This is NOT a hacking tool. It is a professional OSINT + metadata +
threat-modeling automation system.
"""

import sys
import argparse
from pathlib import Path
from redops.pipelines.loader import PipelineLoader
from redops.pipelines.runner import PipelineRunner
from redops.core.config import RedOpsConfig


__version__ = "1.5.0"


def run_pipeline(
    pipeline_path: str,
    target: str,
    output_dir: str = "./output",
    config_path: str = None,
):
    """
    Run a pipeline on a target.

    Args:
        pipeline_path: Path to the pipeline JSON file
        target: Target (domain, directory, etc.)
        output_dir: Output directory for reports
        config_path: Optional path to config file
    """
    try:
        # Load configuration
        if config_path:
            config = RedOpsConfig.from_file(Path(config_path))
        else:
            config = RedOpsConfig.from_env()

        # Override output directory if specified
        if output_dir:
            config.output.output_dir = output_dir

        print(f"[RedOps] Loading pipeline: {pipeline_path}")

        # Load the pipeline
        pipeline = PipelineLoader.load(pipeline_path)

        print(f"[RedOps] Pipeline: {pipeline.metadata.name}")
        print(f"[RedOps] Target: {target}")
        print(f"[RedOps] Steps: {len(pipeline.enabled_steps)}")
        print()

        # Create the runner with config
        runner = PipelineRunner(pipeline, config=config)

        # Run the pipeline
        print("[RedOps] Starting pipeline execution...")
        ctx = runner.run(target=target)

        print()
        print("[RedOps] Pipeline completed successfully!")
        print()

        # Print summary
        print("=== Execution Summary ===")
        print(f"Target: {ctx.target}")
        print(f"Total logs: {len(ctx.logs)}")
        print(f"Data keys: {len(ctx.data)}")
        print()

        # Print errors and warnings
        errors = ctx.get_logs(level="ERROR")
        warnings = ctx.get_logs(level="WARNING")

        if errors:
            print(f"⚠️  Errors: {len(errors)}")
            for error in errors[:5]:
                print(f"  - {error.get('message')}")
            print()

        if warnings:
            print(f"⚠️  Warnings: {len(warnings)}")
            for warning in warnings[:5]:
                print(f"  - {warning.get('message')}")
            print()

        # Print output paths
        print("=== Output Files ===")
        for key in ctx.data.keys():
            if "_path" in key:
                print(f"  {key}: {ctx.data[key]}")

        print()
        print("[RedOps] Done!")

        return 0

    except (RuntimeError, ImportError, OSError, ValueError, TypeError, ConnectionError) as e:
        print(f"[RedOps] ERROR: {e}", file=sys.stderr)
        if config and config.output.verbose:
            import traceback

            traceback.print_exc()
        return 1


def list_pipelines(directory: str = "./config/pipelines"):
    """
    List available pipelines.

    Args:
        directory: Directory containing pipeline files
    """
    pipeline_dir = Path(directory)

    if not pipeline_dir.exists():
        print(f"Pipeline directory not found: {directory}")
        return

    print("Available pipelines:")
    print()

    for pipeline_file in pipeline_dir.glob("*.json"):
        try:
            pipeline = PipelineLoader.load(pipeline_file)
            print(f"  • {pipeline.metadata.name}")
            if pipeline.metadata.description:
                print(f"    {pipeline.metadata.description}")
            print(f"    File: {pipeline_file.name}")
            print(f"    Steps: {len(pipeline.steps)}")
            print()
        except (ValueError, OSError, TypeError) as e:
            print(f"  • {pipeline_file.name} (error loading: {e})")
            print()


def main():
    """Main entry point for RedOps CLI.

    This uses the enhanced CLI from redops.cli.app.
    For legacy pipeline-based execution, use run_pipeline() directly.
    """
    from redops.cli.app import main as cli_main

    sys.exit(cli_main())


def main_legacy():
    """Legacy main entry point for RedOps CLI."""
    parser = argparse.ArgumentParser(
        description="RedOps - OSINT and Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  redops run config/pipelines/recon_pipeline.json example.com
  redops run config/pipelines/forensic_pipeline.json /path/to/directory --output-dir ./reports
  redops list
        """,
    )

    parser.add_argument("--version", action="version", version=f"RedOps {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run a pipeline")
    run_parser.add_argument("pipeline", help="Path to pipeline JSON file")
    run_parser.add_argument("target", help="Target (domain, directory, etc.)")
    run_parser.add_argument(
        "--output-dir", "-o", default="./output", help="Output directory"
    )
    run_parser.add_argument("--config", "-c", help="Path to config file")

    # List command
    list_parser = subparsers.add_parser("list", help="List available pipelines")
    list_parser.add_argument(
        "--dir", default="./config/pipelines", help="Pipeline directory"
    )

    args = parser.parse_args()

    if args.command == "run":
        sys.exit(run_pipeline(args.pipeline, args.target, args.output_dir, args.config))
    elif args.command == "list":
        list_pipelines(args.dir)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
