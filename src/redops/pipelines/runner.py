"""
Pipeline runner - Executes pipelines step by step.

Supports:
- Sequential execution (default)
- Parallel execution via parallel_group
- Dependency-based execution via depends_on
"""

import importlib
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional, List, Dict, TYPE_CHECKING
from redops.pipelines.schemas import Pipeline, PipelineStep
from redops.core.context import Context
from redops.core.plugin_system import (
    PluginRegistry,
    HookPoint,
    ModulePlugin,
    PluginType,
    PluginState,
    get_plugin_registry,
)

if TYPE_CHECKING:
    from redops.core.config import RedOpsConfig


class PipelineRunner:
    """
    Executes pipelines by running each step sequentially and
    passing a Context object through the chain.

    Supports parallel execution for steps with the same parallel_group.

    Integrates with the plugin system to:
    - Execute hooks at pipeline lifecycle points
    - Support ModulePlugin-based modules alongside function modules
    """

    def __init__(
        self,
        pipeline: Pipeline,
        config: Optional["RedOpsConfig"] = None,
        plugin_registry: Optional[PluginRegistry] = None,
        max_workers: int = 4,
    ):
        """
        Initialize the runner with a pipeline.

        Args:
            pipeline: The pipeline to execute
            config: RedOps configuration (scope, output settings, etc.)
            plugin_registry: Plugin registry (uses global if not provided)
            max_workers: Maximum number of parallel workers
        """
        self.pipeline = pipeline
        self.config = config
        self.plugins = plugin_registry or get_plugin_registry()
        self.max_workers = max_workers

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

        Supports both function-based modules and plugin-based modules.
        Executes BEFORE_MODULE and AFTER_MODULE hooks.

        Args:
            step: The step to execute
            ctx: The current context

        Returns:
            The updated context
        """
        ctx.log(f"Executing step: {step.name}", level="INFO", step=step.name)

        # Execute BEFORE_MODULE hooks
        self.plugins.execute_hooks(
            HookPoint.BEFORE_MODULE,
            ctx,
            module_name=step.name,
        )

        try:
            result = {}

            # Check if this is a plugin-based module
            plugin_instance = self._get_plugin_module(step.module)

            if plugin_instance:
                # Execute plugin module
                if plugin_instance.validate_target(ctx.target or ""):
                    result = plugin_instance.execute(ctx)
                    # Plugin returns dict, merge into context
                    if result:
                        for key, value in result.items():
                            ctx.add(key, value)
                else:
                    ctx.log(
                        f"Plugin {step.name} skipped: invalid target",
                        level="WARNING",
                        step=step.name,
                    )
            else:
                # Resolve and execute function-based module
                func = self._resolve_module_function(step.module)
                ctx = func(ctx, step.params)

            ctx.log(f"Step completed: {step.name}", level="INFO", step=step.name)

            # Execute AFTER_MODULE hooks
            self.plugins.execute_hooks(
                HookPoint.AFTER_MODULE,
                ctx,
                module_name=step.name,
                result=result,
            )

            return ctx

        except Exception as e:
            error_msg = f"Step failed: {step.name} - {str(e)}"
            ctx.log(error_msg, level="ERROR", step=step.name, error=str(e))

            # Execute ON_ERROR hooks
            self.plugins.execute_hooks(
                HookPoint.ON_ERROR,
                ctx,
                error=e,
            )

            if not step.continue_on_error:
                raise RuntimeError(error_msg) from e

            return ctx

    def _get_plugin_module(self, module_path: str) -> Optional[ModulePlugin]:
        """
        Check if a module path refers to a registered plugin.

        Args:
            module_path: Module path (e.g., "plugin:shodan_recon")

        Returns:
            ModulePlugin instance if found, None otherwise
        """
        # Plugin modules are prefixed with "plugin:"
        if not module_path.startswith("plugin:"):
            return None

        plugin_name = module_path[7:]  # Remove "plugin:" prefix
        plugin_info = self.plugins.get(plugin_name)

        if plugin_info is None:
            return None

        if plugin_info.state != PluginState.ACTIVE:
            return None

        if plugin_info.metadata.plugin_type != PluginType.MODULE:
            return None

        instance = plugin_info.instance
        if isinstance(instance, ModulePlugin):
            return instance

        return None

    def _group_steps_for_execution(
        self, steps: List[PipelineStep]
    ) -> List[List[PipelineStep]]:
        """
        Group steps into execution batches.

        Steps with the same parallel_group are grouped together and run concurrently.
        Steps without a parallel_group run sequentially.

        Args:
            steps: List of pipeline steps

        Returns:
            List of step batches (each batch runs concurrently)
        """
        batches: List[List[PipelineStep]] = []
        current_group: Optional[str] = None
        current_batch: List[PipelineStep] = []

        for step in steps:
            if step.parallel_group is None:
                # Sequential step - flush current batch and add as single step
                if current_batch:
                    batches.append(current_batch)
                    current_batch = []
                    current_group = None
                batches.append([step])
            elif step.parallel_group == current_group:
                # Same parallel group - add to current batch
                current_batch.append(step)
            else:
                # New parallel group - flush current batch and start new one
                if current_batch:
                    batches.append(current_batch)
                current_batch = [step]
                current_group = step.parallel_group

        # Flush final batch
        if current_batch:
            batches.append(current_batch)

        return batches

    def _execute_parallel_batch(
        self, batch: List[PipelineStep], ctx: Context
    ) -> Context:
        """
        Execute a batch of steps in parallel.

        Each step gets a copy of the context, and results are merged back.

        Args:
            batch: List of steps to run in parallel
            ctx: Current context

        Returns:
            Updated context with merged results
        """
        if len(batch) == 1:
            # Single step - run directly
            return self._execute_step(batch[0], ctx)

        ctx.log(
            f"Starting parallel batch: {[s.name for s in batch]}",
            level="INFO",
        )

        # Track results from each parallel execution
        step_results: Dict[str, Dict] = {}
        step_logs: Dict[str, List] = {}
        errors: List[str] = []

        def run_step(step: PipelineStep) -> tuple:
            """Execute a step in a thread."""
            # Create a fresh context copy for this thread
            step_ctx = Context(target=ctx.target, config=ctx.config)
            # Copy existing data
            step_ctx.data = copy.deepcopy(ctx.data)
            step_ctx.metadata = copy.deepcopy(ctx.metadata)

            try:
                result_ctx = self._execute_step(step, step_ctx)
                return (step.name, result_ctx.data, result_ctx.logs, None)
            except Exception as e:
                return (step.name, {}, [], str(e))

        # Run steps in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(
            max_workers=min(len(batch), self.max_workers)
        ) as executor:
            futures = {executor.submit(run_step, step): step for step in batch}

            for future in as_completed(futures):
                step_name, data, logs, error = future.result()
                if error:
                    errors.append(f"{step_name}: {error}")
                    step = futures[future]
                    if not step.continue_on_error:
                        # Cancel remaining futures (best effort)
                        for f in futures:
                            f.cancel()
                        raise RuntimeError(f"Parallel step failed: {error}")
                else:
                    step_results[step_name] = data
                    step_logs[step_name] = logs

        # Merge results back into main context
        for step_name, data in step_results.items():
            for key, value in data.items():
                # Skip pipeline metadata that was copied
                if key not in ("pipeline_name", "pipeline_version"):
                    ctx.data[key] = value

        # Merge logs
        for step_name, logs in step_logs.items():
            for log_entry in logs:
                # Avoid duplicating logs we already have
                if log_entry not in ctx.logs:
                    ctx.logs.append(log_entry)

        ctx.log(
            f"Completed parallel batch: {[s.name for s in batch]}",
            level="INFO",
        )

        return ctx

    def run(
        self,
        target: Optional[str] = None,
        initial_context: Optional[Context] = None,
        parallel: bool = True,
    ) -> Context:
        """
        Run the pipeline.

        Executes BEFORE_PIPELINE and AFTER_PIPELINE hooks around the
        pipeline execution. Supports parallel execution of steps with
        the same parallel_group.

        Args:
            target: The target for the pipeline (domain, directory, etc.)
            initial_context: Optional pre-existing context to use
            parallel: Enable parallel execution (default True)

        Returns:
            The final context after all steps
        """
        # Create or use existing context
        ctx = initial_context or Context(target=target, config=self.config)

        # Add pipeline metadata to context
        ctx.add("pipeline_name", self.pipeline.metadata.name)
        ctx.add("pipeline_version", self.pipeline.metadata.version)

        ctx.log(f"Starting pipeline: {self.pipeline.metadata.name}", level="INFO")
        ctx.log(f"Target: {target or 'N/A'}", level="INFO")

        # Execute BEFORE_PIPELINE hooks
        self.plugins.execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)

        if parallel:
            # Group steps into batches for parallel execution
            batches = self._group_steps_for_execution(self.pipeline.enabled_steps)

            for batch in batches:
                ctx = self._execute_parallel_batch(batch, ctx)
        else:
            # Sequential execution (original behavior)
            for step in self.pipeline.enabled_steps:
                ctx = self._execute_step(step, ctx)

        # Execute AFTER_PIPELINE hooks
        self.plugins.execute_hooks(HookPoint.AFTER_PIPELINE, ctx)

        ctx.log(f"Pipeline completed: {self.pipeline.metadata.name}", level="INFO")
        return ctx
