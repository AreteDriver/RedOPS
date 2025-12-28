"""
Pipeline runner - Executes pipelines step by step.
"""

import importlib
from typing import Callable, Optional
from redops.pipelines.schemas import Pipeline, PipelineStep
from redops.core.context import Context


class PipelineRunner:
    """
    Executes pipelines by running each step sequentially and
    passing a Context object through the chain.
    """

    def __init__(self, pipeline: Pipeline):
        """
        Initialize the runner with a pipeline.

        Args:
            pipeline: The pipeline to execute
        """
        self.pipeline = pipeline

    def _resolve_module_function(self, module_path: str) -> Callable:
        """
        Resolve a dotted module path to a callable function.

        Args:
            module_path: Dotted path like "recon.domains.profile_domain"

        Returns:
            The callable function

        Raises:
            ImportError: If module cannot be imported
            AttributeError: If function doesn't exist in module
        """
        parts = module_path.split(".")

        # The module path is relative to redops.modules
        module_name = f"redops.modules.{'.'.join(parts[:-1])}"
        function_name = parts[-1]

        try:
            module = importlib.import_module(module_name)
            func = getattr(module, function_name)
            return func
        except ImportError as e:
            raise ImportError(f"Cannot import module '{module_name}': {e}")
        except AttributeError as e:
            raise AttributeError(
                f"Function '{function_name}' not found in module '{module_name}': {e}"
            )

    def _execute_step(self, step: PipelineStep, ctx: Context) -> Context:
        """
        Execute a single pipeline step.

        Args:
            step: The step to execute
            ctx: The current context

        Returns:
            The updated context
        """
        ctx.log(f"Executing step: {step.name}", level="INFO", step=step.name)

        try:
            # Resolve the module function
            func = self._resolve_module_function(step.module)

            # Execute the function with context and params
            ctx = func(ctx, step.params)

            ctx.log(f"Step completed: {step.name}", level="INFO", step=step.name)
            return ctx

        except Exception as e:
            error_msg = f"Step failed: {step.name} - {str(e)}"
            ctx.log(error_msg, level="ERROR", step=step.name, error=str(e))

            if not step.continue_on_error:
                raise RuntimeError(error_msg) from e

            return ctx

    def run(
        self, target: Optional[str] = None, initial_context: Optional[Context] = None
    ) -> Context:
        """
        Run the pipeline.

        Args:
            target: The target for the pipeline (domain, directory, etc.)
            initial_context: Optional pre-existing context to use

        Returns:
            The final context after all steps
        """
        # Create or use existing context
        ctx = initial_context or Context(target=target)

        # Add pipeline metadata to context
        ctx.add("pipeline_name", self.pipeline.metadata.name)
        ctx.add("pipeline_version", self.pipeline.metadata.version)

        ctx.log(f"Starting pipeline: {self.pipeline.metadata.name}", level="INFO")
        ctx.log(f"Target: {target or 'N/A'}", level="INFO")

        # Execute each enabled step
        for step in self.pipeline.enabled_steps:
            ctx = self._execute_step(step, ctx)

        ctx.log(f"Pipeline completed: {self.pipeline.metadata.name}", level="INFO")
        return ctx
