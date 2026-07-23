"""
Workflow Engine Module for RedOPS.

Provides DAG-based workflows, state machines, conditional branching,
and parallel execution for orchestrating security operations.
"""

import threading
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


class TaskState(Enum):
    """State of a workflow task."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class WorkflowState(Enum):
    """State of a workflow."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class TransitionType(Enum):
    """Types of state machine transitions."""

    AUTOMATIC = "automatic"
    CONDITIONAL = "conditional"
    MANUAL = "manual"


@dataclass
class TaskResult:
    """Result of a task execution."""

    task_id: str
    state: TaskState
    output: Any = None
    error: Exception | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    retries: int = 0

    @property
    def duration(self) -> float | None:
        """Get task duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def success(self) -> bool:
        """Check if task completed successfully."""
        return self.state == TaskState.COMPLETED


@dataclass
class WorkflowContext:
    """Context passed between workflow tasks."""

    workflow_id: str
    variables: dict[str, Any] = field(default_factory=dict)
    results: dict[str, TaskResult] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a variable from context."""
        return self.variables.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a variable in context."""
        self.variables[key] = value

    def get_result(self, task_id: str) -> TaskResult | None:
        """Get result of a specific task."""
        return self.results.get(task_id)

    def get_output(self, task_id: str, default: Any = None) -> Any:
        """Get output of a specific task."""
        result = self.results.get(task_id)
        return result.output if result else default


class Task(ABC):
    """Base class for workflow tasks."""

    def __init__(
        self,
        task_id: str | None = None,
        name: str | None = None,
        retries: int = 0,
        retry_delay: float = 1.0,
        timeout: float | None = None,
    ):
        """Initialize task."""
        self._id = task_id or str(uuid.uuid4())
        self._name = name or self.__class__.__name__
        self._retries = retries
        self._retry_delay = retry_delay
        self._timeout = timeout
        self._state = TaskState.PENDING
        self._dependencies: set[str] = set()

    @property
    def id(self) -> str:
        """Get task ID."""
        return self._id

    @property
    def name(self) -> str:
        """Get task name."""
        return self._name

    @property
    def state(self) -> TaskState:
        """Get task state."""
        return self._state

    @state.setter
    def state(self, value: TaskState) -> None:
        """Set task state."""
        self._state = value

    @property
    def dependencies(self) -> set[str]:
        """Get task dependencies."""
        return self._dependencies

    def depends_on(self, *task_ids: str) -> "Task":
        """Add dependencies to this task."""
        self._dependencies.update(task_ids)
        return self

    @abstractmethod
    def execute(self, context: WorkflowContext) -> Any:
        """Execute the task."""
        pass

    def on_success(self, context: WorkflowContext, result: Any) -> None:
        """Called when task succeeds."""
        pass

    def on_failure(self, context: WorkflowContext, error: Exception) -> None:
        """Called when task fails."""
        pass


class FunctionTask(Task):
    """Task that executes a function."""

    def __init__(
        self,
        func: Callable[[WorkflowContext], Any],
        task_id: str | None = None,
        name: str | None = None,
        **kwargs,
    ):
        """Initialize function task."""
        super().__init__(task_id, name or func.__name__, **kwargs)
        self._func = func

    def execute(self, context: WorkflowContext) -> Any:
        """Execute the function."""
        return self._func(context)


class ConditionalTask(Task):
    """Task that branches based on a condition."""

    def __init__(
        self,
        condition: Callable[[WorkflowContext], bool],
        if_true: str | None = None,
        if_false: str | None = None,
        task_id: str | None = None,
        name: str | None = None,
        **kwargs,
    ):
        """Initialize conditional task."""
        super().__init__(task_id, name or "conditional", **kwargs)
        self._condition = condition
        self._if_true = if_true
        self._if_false = if_false

    @property
    def if_true(self) -> str | None:
        """Get task ID to execute if condition is true."""
        return self._if_true

    @property
    def if_false(self) -> str | None:
        """Get task ID to execute if condition is false."""
        return self._if_false

    def execute(self, context: WorkflowContext) -> bool:
        """Evaluate the condition."""
        return self._condition(context)


class ParallelTask(Task):
    """Task that executes multiple tasks in parallel."""

    def __init__(
        self,
        tasks: list[Task],
        task_id: str | None = None,
        name: str | None = None,
        max_workers: int = 4,
        fail_fast: bool = True,
        **kwargs,
    ):
        """Initialize parallel task."""
        super().__init__(task_id, name or "parallel", **kwargs)
        self._tasks = tasks
        self._max_workers = max_workers
        self._fail_fast = fail_fast

    @property
    def tasks(self) -> list[Task]:
        """Get parallel tasks."""
        return self._tasks

    def execute(self, context: WorkflowContext) -> dict[str, TaskResult]:
        """Execute tasks in parallel."""
        results = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {
                executor.submit(self._execute_task, task, context): task
                for task in self._tasks
            }

            for future in as_completed(futures):
                task = futures[future]
                try:
                    result = future.result()
                    results[task.id] = result
                    if self._fail_fast and not result.success:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break
                except (OSError, RuntimeError, TypeError, ValueError) as e:
                    results[task.id] = TaskResult(
                        task_id=task.id,
                        state=TaskState.FAILED,
                        error=e,
                    )
                    if self._fail_fast:
                        for f in futures:
                            f.cancel()
                        break

        return results

    def _execute_task(self, task: Task, context: WorkflowContext) -> TaskResult:
        """Execute a single task."""
        start_time = datetime.now(timezone.utc)
        try:
            output = task.execute(context)
            return TaskResult(
                task_id=task.id,
                state=TaskState.COMPLETED,
                output=output,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
            )
        except (OSError, RuntimeError, TypeError, ValueError) as e:
            return TaskResult(
                task_id=task.id,
                state=TaskState.FAILED,
                error=e,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
            )


class SubWorkflowTask(Task):
    """Task that executes a sub-workflow."""

    def __init__(
        self,
        workflow: "Workflow",
        task_id: str | None = None,
        name: str | None = None,
        **kwargs,
    ):
        """Initialize sub-workflow task."""
        super().__init__(task_id, name or f"sub_{workflow.id}", **kwargs)
        self._workflow = workflow

    def execute(self, context: WorkflowContext) -> WorkflowContext:
        """Execute the sub-workflow."""
        # Create child context
        child_context = WorkflowContext(
            workflow_id=self._workflow.id,
            variables=dict(context.variables),
            metadata=dict(context.metadata),
        )

        # Execute workflow
        executor = WorkflowExecutor()
        return executor.execute(self._workflow, child_context)


class Workflow:
    """DAG-based workflow definition."""

    def __init__(
        self,
        workflow_id: str | None = None,
        name: str = "workflow",
        description: str = "",
    ):
        """Initialize workflow."""
        self._id = workflow_id or str(uuid.uuid4())
        self._name = name
        self._description = description
        self._tasks: dict[str, Task] = {}
        self._entry_point: str | None = None
        self._state = WorkflowState.PENDING

    @property
    def id(self) -> str:
        """Get workflow ID."""
        return self._id

    @property
    def name(self) -> str:
        """Get workflow name."""
        return self._name

    @property
    def description(self) -> str:
        """Get workflow description."""
        return self._description

    @property
    def state(self) -> WorkflowState:
        """Get workflow state."""
        return self._state

    @state.setter
    def state(self, value: WorkflowState) -> None:
        """Set workflow state."""
        self._state = value

    @property
    def tasks(self) -> dict[str, Task]:
        """Get all tasks."""
        return self._tasks

    def add_task(self, task: Task) -> "Workflow":
        """Add a task to the workflow."""
        self._tasks[task.id] = task
        if self._entry_point is None:
            self._entry_point = task.id
        return self

    def set_entry_point(self, task_id: str) -> "Workflow":
        """Set the workflow entry point."""
        if task_id not in self._tasks:
            raise ValueError(f"Task {task_id} not found in workflow")
        self._entry_point = task_id
        return self

    def get_task(self, task_id: str) -> Task | None:
        """Get a task by ID."""
        return self._tasks.get(task_id)

    def get_ready_tasks(self, completed: set[str]) -> list[Task]:
        """Get tasks that are ready to execute."""
        ready = []
        for task_id, task in self._tasks.items():
            if task_id not in completed and task.state == TaskState.PENDING:
                if task.dependencies.issubset(completed):
                    ready.append(task)
        return ready

    def get_execution_order(self) -> list[str]:
        """Get topological execution order."""
        visited = set()
        order = []

        def visit(task_id: str):
            if task_id in visited:
                return
            visited.add(task_id)
            task = self._tasks.get(task_id)
            if task:
                for dep in task.dependencies:
                    visit(dep)
                order.append(task_id)

        for task_id in self._tasks:
            visit(task_id)

        return order

    def validate(self) -> list[str]:
        """Validate workflow structure."""
        errors = []

        # Check for missing dependencies
        for task_id, task in self._tasks.items():
            for dep in task.dependencies:
                if dep not in self._tasks:
                    errors.append(f"Task {task_id} depends on missing task {dep}")

        # Check for cycles
        if self._has_cycle():
            errors.append("Workflow contains a cycle")

        # Check entry point
        if self._entry_point and self._entry_point not in self._tasks:
            errors.append(f"Entry point {self._entry_point} not found")

        return errors

    def _has_cycle(self) -> bool:
        """Check if workflow has cycles."""
        WHITE, GRAY, BLACK = 0, 1, 2
        colors = {task_id: WHITE for task_id in self._tasks}

        def dfs(task_id: str) -> bool:
            colors[task_id] = GRAY
            task = self._tasks.get(task_id)
            if task:
                for dep in task.dependencies:
                    if colors.get(dep) == GRAY:
                        return True
                    if colors.get(dep) == WHITE and dfs(dep):
                        return True
            colors[task_id] = BLACK
            return False

        for task_id in self._tasks:
            if colors[task_id] == WHITE:
                if dfs(task_id):
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize workflow to dictionary."""
        return {
            "id": self._id,
            "name": self._name,
            "description": self._description,
            "state": self._state.value,
            "entry_point": self._entry_point,
            "tasks": {
                task_id: {
                    "id": task.id,
                    "name": task.name,
                    "state": task.state.value,
                    "dependencies": list(task.dependencies),
                }
                for task_id, task in self._tasks.items()
            },
        }


class WorkflowExecutor:
    """Executes workflows."""

    def __init__(
        self,
        max_parallel: int = 4,
        on_task_start: Callable[[Task], None] | None = None,
        on_task_complete: Callable[[Task, TaskResult], None] | None = None,
        on_workflow_complete: Callable[[Workflow, WorkflowContext], None] | None = None,
    ):
        """Initialize executor."""
        self._max_parallel = max_parallel
        self._on_task_start = on_task_start
        self._on_task_complete = on_task_complete
        self._on_workflow_complete = on_workflow_complete

    def execute(
        self, workflow: Workflow, context: WorkflowContext | None = None
    ) -> WorkflowContext:
        """Execute a workflow."""
        if context is None:
            context = WorkflowContext(workflow_id=workflow.id)

        # Validate workflow
        errors = workflow.validate()
        if errors:
            raise ValueError(f"Invalid workflow: {errors}")

        workflow.state = WorkflowState.RUNNING
        completed: set[str] = set()
        skipped: set[str] = set()

        try:
            while True:
                ready_tasks = workflow.get_ready_tasks(completed | skipped)
                if not ready_tasks:
                    # Check if all tasks are done
                    if len(completed) + len(skipped) >= len(workflow.tasks):
                        break
                    # No ready tasks but not all done - might be blocked
                    remaining = set(workflow.tasks.keys()) - completed - skipped
                    if remaining:
                        # Check if remaining tasks can ever run
                        can_run = False
                        for task_id in remaining:
                            task = workflow.get_task(task_id)
                            if task and task.dependencies.issubset(completed | skipped):
                                can_run = True
                                break
                        if not can_run:
                            break
                    else:
                        break

                # Execute ready tasks
                if len(ready_tasks) == 1:
                    # Single task - execute directly
                    result = self._execute_task(ready_tasks[0], context, workflow)
                    if result.success:
                        completed.add(ready_tasks[0].id)
                    else:
                        # Task failed - skip dependent tasks
                        self._skip_dependents(
                            workflow, ready_tasks[0].id, skipped, context
                        )
                        completed.add(ready_tasks[0].id)
                else:
                    # Multiple tasks - execute in parallel
                    results = self._execute_parallel(ready_tasks, context, workflow)
                    for task_id, result in results.items():
                        if result.success:
                            completed.add(task_id)
                        else:
                            self._skip_dependents(workflow, task_id, skipped, context)
                            completed.add(task_id)

            # Determine final state
            failed_tasks = [
                tid
                for tid, result in context.results.items()
                if result.state == TaskState.FAILED
            ]
            if failed_tasks:
                workflow.state = WorkflowState.FAILED
            else:
                workflow.state = WorkflowState.COMPLETED

        except (OSError, RuntimeError, TypeError, ValueError):
            workflow.state = WorkflowState.FAILED
            raise

        if self._on_workflow_complete:
            self._on_workflow_complete(workflow, context)

        return context

    def _execute_task(
        self, task: Task, context: WorkflowContext, workflow: Workflow
    ) -> TaskResult:
        """Execute a single task with retries."""
        if self._on_task_start:
            self._on_task_start(task)

        task.state = TaskState.RUNNING
        start_time = datetime.now(timezone.utc)
        retries = 0
        last_error = None

        while retries <= task._retries:
            try:
                output = task.execute(context)

                # Handle conditional tasks
                if isinstance(task, ConditionalTask):
                    if output and task.if_true:
                        # Skip false branch tasks
                        if task.if_false:
                            self._skip_task(workflow, task.if_false, context)
                    elif not output and task.if_false:
                        # Skip true branch tasks
                        if task.if_true:
                            self._skip_task(workflow, task.if_true, context)

                result = TaskResult(
                    task_id=task.id,
                    state=TaskState.COMPLETED,
                    output=output,
                    start_time=start_time,
                    end_time=datetime.now(timezone.utc),
                    retries=retries,
                )
                task.state = TaskState.COMPLETED
                task.on_success(context, output)
                context.results[task.id] = result

                if self._on_task_complete:
                    self._on_task_complete(task, result)

                return result

            except (OSError, RuntimeError, TypeError, ValueError) as e:
                last_error = e
                retries += 1
                if retries <= task._retries:
                    import time

                    time.sleep(task._retry_delay)

        # All retries failed
        result = TaskResult(
            task_id=task.id,
            state=TaskState.FAILED,
            error=last_error,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            retries=retries - 1,
        )
        task.state = TaskState.FAILED
        task.on_failure(context, last_error)
        context.results[task.id] = result

        if self._on_task_complete:
            self._on_task_complete(task, result)

        return result

    def _execute_parallel(
        self, tasks: list[Task], context: WorkflowContext, workflow: Workflow
    ) -> dict[str, TaskResult]:
        """Execute multiple tasks in parallel."""
        results = {}

        with ThreadPoolExecutor(
            max_workers=min(len(tasks), self._max_parallel)
        ) as executor:
            futures = {
                executor.submit(self._execute_task, task, context, workflow): task
                for task in tasks
            }

            for future in as_completed(futures):
                task = futures[future]
                try:
                    result = future.result()
                    results[task.id] = result
                except (OSError, RuntimeError, TypeError, ValueError) as e:
                    results[task.id] = TaskResult(
                        task_id=task.id,
                        state=TaskState.FAILED,
                        error=e,
                    )

        return results

    def _skip_task(
        self, workflow: Workflow, task_id: str, context: WorkflowContext
    ) -> None:
        """Skip a task."""
        task = workflow.get_task(task_id)
        if task and task.state == TaskState.PENDING:
            task.state = TaskState.SKIPPED
            context.results[task_id] = TaskResult(
                task_id=task_id,
                state=TaskState.SKIPPED,
            )

    def _skip_dependents(
        self,
        workflow: Workflow,
        failed_task_id: str,
        skipped: set[str],
        context: WorkflowContext,
    ) -> None:
        """Skip all tasks that depend on a failed task."""
        for task_id, task in workflow.tasks.items():
            if failed_task_id in task.dependencies and task.state == TaskState.PENDING:
                task.state = TaskState.SKIPPED
                skipped.add(task_id)
                context.results[task_id] = TaskResult(
                    task_id=task_id,
                    state=TaskState.SKIPPED,
                )
                self._skip_dependents(workflow, task_id, skipped, context)


@dataclass
class StateTransition:
    """A state machine transition."""

    from_state: str
    to_state: str
    event: str
    condition: Callable[[dict[str, Any]], bool] | None = None
    action: Callable[[dict[str, Any]], None] | None = None
    transition_type: TransitionType = TransitionType.AUTOMATIC


class StateMachine:
    """Finite state machine implementation."""

    def __init__(self, name: str = "state_machine", initial_state: str | None = None):
        """Initialize state machine."""
        self._name = name
        self._states: set[str] = set()
        self._transitions: list[StateTransition] = []
        self._current_state: str | None = initial_state
        self._initial_state = initial_state
        self._final_states: set[str] = set()
        self._state_handlers: dict[str, Callable[[dict[str, Any]], None]] = {}
        self._context: dict[str, Any] = {}
        self._history: list[tuple[str, str, str]] = []  # (from, event, to)
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        """Get state machine name."""
        return self._name

    @property
    def current_state(self) -> str | None:
        """Get current state."""
        return self._current_state

    @property
    def states(self) -> set[str]:
        """Get all states."""
        return self._states

    @property
    def history(self) -> list[tuple[str, str, str]]:
        """Get transition history."""
        return list(self._history)

    @property
    def context(self) -> dict[str, Any]:
        """Get state machine context."""
        return self._context

    def add_state(self, state: str, is_final: bool = False) -> "StateMachine":
        """Add a state."""
        self._states.add(state)
        if is_final:
            self._final_states.add(state)
        return self

    def add_transition(
        self,
        from_state: str,
        to_state: str,
        event: str,
        condition: Callable[[dict[str, Any]], bool] | None = None,
        action: Callable[[dict[str, Any]], None] | None = None,
        transition_type: TransitionType = TransitionType.AUTOMATIC,
    ) -> "StateMachine":
        """Add a transition."""
        self._states.add(from_state)
        self._states.add(to_state)
        self._transitions.append(
            StateTransition(
                from_state=from_state,
                to_state=to_state,
                event=event,
                condition=condition,
                action=action,
                transition_type=transition_type,
            )
        )
        return self

    def set_state_handler(
        self, state: str, handler: Callable[[dict[str, Any]], None]
    ) -> "StateMachine":
        """Set a handler to be called when entering a state."""
        self._state_handlers[state] = handler
        return self

    def set_initial_state(self, state: str) -> "StateMachine":
        """Set the initial state."""
        self._states.add(state)
        self._initial_state = state
        self._current_state = state
        return self

    def reset(self) -> None:
        """Reset state machine to initial state."""
        with self._lock:
            self._current_state = self._initial_state
            self._history.clear()
            self._context.clear()

    def can_trigger(self, event: str) -> bool:
        """Check if an event can be triggered from current state."""
        with self._lock:
            for transition in self._transitions:
                if (
                    transition.from_state == self._current_state
                    and transition.event == event
                ):
                    if transition.condition is None or transition.condition(
                        self._context
                    ):
                        return True
            return False

    def trigger(self, event: str, **context_updates) -> bool:
        """Trigger an event."""
        with self._lock:
            # Update context
            self._context.update(context_updates)

            # Find matching transition
            for transition in self._transitions:
                if (
                    transition.from_state == self._current_state
                    and transition.event == event
                ):
                    # Check condition
                    if transition.condition and not transition.condition(self._context):
                        continue

                    # Execute action
                    if transition.action:
                        transition.action(self._context)

                    # Record history
                    self._history.append(
                        (
                            self._current_state,
                            event,
                            transition.to_state,
                        )
                    )

                    # Transition to new state
                    self._current_state = transition.to_state

                    # Call state handler
                    if transition.to_state in self._state_handlers:
                        self._state_handlers[transition.to_state](self._context)

                    return True

            return False

    def is_final(self) -> bool:
        """Check if current state is final."""
        return self._current_state in self._final_states

    def get_available_events(self) -> list[str]:
        """Get events that can be triggered from current state."""
        with self._lock:
            events = []
            for transition in self._transitions:
                if transition.from_state == self._current_state:
                    if transition.condition is None or transition.condition(
                        self._context
                    ):
                        events.append(transition.event)
            return events

    def to_dict(self) -> dict[str, Any]:
        """Serialize state machine to dictionary."""
        return {
            "name": self._name,
            "current_state": self._current_state,
            "initial_state": self._initial_state,
            "states": list(self._states),
            "final_states": list(self._final_states),
            "transitions": [
                {
                    "from": t.from_state,
                    "to": t.to_state,
                    "event": t.event,
                    "type": t.transition_type.value,
                }
                for t in self._transitions
            ],
            "history": self._history,
            "context": self._context,
        }


class WorkflowBuilder:
    """Fluent builder for creating workflows."""

    def __init__(self, name: str = "workflow"):
        """Initialize builder."""
        self._workflow = Workflow(name=name)
        self._last_task_id: str | None = None

    def add_task(
        self,
        func: Callable[[WorkflowContext], Any],
        task_id: str | None = None,
        name: str | None = None,
        **kwargs,
    ) -> "WorkflowBuilder":
        """Add a function task."""
        task = FunctionTask(func, task_id, name, **kwargs)
        self._workflow.add_task(task)
        self._last_task_id = task.id
        return self

    def add_conditional(
        self,
        condition: Callable[[WorkflowContext], bool],
        if_true: str | None = None,
        if_false: str | None = None,
        task_id: str | None = None,
        **kwargs,
    ) -> "WorkflowBuilder":
        """Add a conditional task."""
        task = ConditionalTask(condition, if_true, if_false, task_id, **kwargs)
        self._workflow.add_task(task)
        self._last_task_id = task.id
        return self

    def add_parallel(
        self, tasks: list[Task], task_id: str | None = None, **kwargs
    ) -> "WorkflowBuilder":
        """Add a parallel task."""
        task = ParallelTask(tasks, task_id, **kwargs)
        self._workflow.add_task(task)
        self._last_task_id = task.id
        return self

    def depends_on(self, *task_ids: str) -> "WorkflowBuilder":
        """Add dependencies to the last added task."""
        if self._last_task_id:
            task = self._workflow.get_task(self._last_task_id)
            if task:
                task.depends_on(*task_ids)
        return self

    def set_entry_point(self, task_id: str) -> "WorkflowBuilder":
        """Set the workflow entry point."""
        self._workflow.set_entry_point(task_id)
        return self

    def build(self) -> Workflow:
        """Build and return the workflow."""
        return self._workflow


# Convenience functions
def workflow(name: str = "workflow") -> WorkflowBuilder:
    """Create a new workflow builder."""
    return WorkflowBuilder(name)


def task(
    func: Callable[[WorkflowContext], Any],
    task_id: str | None = None,
    name: str | None = None,
    **kwargs,
) -> FunctionTask:
    """Create a function task."""
    return FunctionTask(func, task_id, name, **kwargs)


def parallel(*tasks: Task, **kwargs) -> ParallelTask:
    """Create a parallel task."""
    return ParallelTask(list(tasks), **kwargs)


def conditional(
    condition: Callable[[WorkflowContext], bool],
    if_true: str | None = None,
    if_false: str | None = None,
    **kwargs,
) -> ConditionalTask:
    """Create a conditional task."""
    return ConditionalTask(condition, if_true, if_false, **kwargs)
