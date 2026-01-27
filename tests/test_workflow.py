"""Tests for the Workflow Engine module."""

import threading
import time


from redops.core.workflow import (
    ConditionalTask,
    FunctionTask,
    ParallelTask,
    StateMachine,
    SubWorkflowTask,
    TaskResult,
    TaskState,
    Workflow,
    WorkflowBuilder,
    WorkflowContext,
    WorkflowExecutor,
    WorkflowState,
    conditional,
    parallel,
    task,
    workflow,
)


class TestTaskState:
    """Tests for TaskState enum."""

    def test_all_states_exist(self):
        """Test all task states are defined."""
        assert TaskState.PENDING.value == "pending"
        assert TaskState.READY.value == "ready"
        assert TaskState.RUNNING.value == "running"
        assert TaskState.COMPLETED.value == "completed"
        assert TaskState.FAILED.value == "failed"
        assert TaskState.SKIPPED.value == "skipped"
        assert TaskState.CANCELLED.value == "cancelled"


class TestWorkflowState:
    """Tests for WorkflowState enum."""

    def test_all_states_exist(self):
        """Test all workflow states are defined."""
        assert WorkflowState.PENDING.value == "pending"
        assert WorkflowState.RUNNING.value == "running"
        assert WorkflowState.COMPLETED.value == "completed"
        assert WorkflowState.FAILED.value == "failed"
        assert WorkflowState.PAUSED.value == "paused"


class TestTaskResult:
    """Tests for TaskResult."""

    def test_basic_result(self):
        """Test basic task result."""
        result = TaskResult(
            task_id="task1",
            state=TaskState.COMPLETED,
            output="success",
        )
        assert result.task_id == "task1"
        assert result.success

    def test_failed_result(self):
        """Test failed task result."""
        result = TaskResult(
            task_id="task1",
            state=TaskState.FAILED,
            error=ValueError("test error"),
        )
        assert not result.success
        assert result.error is not None

    def test_duration(self):
        """Test duration calculation."""
        from datetime import datetime, timezone, timedelta

        start = datetime.now(timezone.utc)
        end = start + timedelta(seconds=5)

        result = TaskResult(
            task_id="task1",
            state=TaskState.COMPLETED,
            start_time=start,
            end_time=end,
        )
        assert result.duration == 5.0


class TestWorkflowContext:
    """Tests for WorkflowContext."""

    def test_basic_context(self):
        """Test basic context creation."""
        ctx = WorkflowContext(workflow_id="wf1")
        assert ctx.workflow_id == "wf1"

    def test_get_set(self):
        """Test getting and setting variables."""
        ctx = WorkflowContext(workflow_id="wf1")
        ctx.set("key", "value")
        assert ctx.get("key") == "value"
        assert ctx.get("missing", "default") == "default"

    def test_get_result(self):
        """Test getting task results."""
        ctx = WorkflowContext(workflow_id="wf1")
        result = TaskResult(task_id="t1", state=TaskState.COMPLETED, output=42)
        ctx.results["t1"] = result

        assert ctx.get_result("t1") == result
        assert ctx.get_output("t1") == 42


class TestFunctionTask:
    """Tests for FunctionTask."""

    def test_basic_execution(self):
        """Test basic function task execution."""

        def my_func(ctx):
            return "hello"

        task = FunctionTask(my_func, task_id="t1")
        ctx = WorkflowContext(workflow_id="wf1")

        result = task.execute(ctx)
        assert result == "hello"

    def test_uses_context(self):
        """Test that task uses context."""

        def my_func(ctx):
            return ctx.get("value") * 2

        task = FunctionTask(my_func)
        ctx = WorkflowContext(workflow_id="wf1")
        ctx.set("value", 21)

        result = task.execute(ctx)
        assert result == 42

    def test_task_name(self):
        """Test task name from function."""

        def custom_name(ctx):
            pass

        task = FunctionTask(custom_name)
        assert task.name == "custom_name"

    def test_dependencies(self):
        """Test task dependencies."""
        task = FunctionTask(lambda ctx: None, task_id="t1")
        task.depends_on("t0")

        assert "t0" in task.dependencies


class TestConditionalTask:
    """Tests for ConditionalTask."""

    def test_condition_true(self):
        """Test conditional task with true condition."""
        task = ConditionalTask(
            condition=lambda ctx: ctx.get("flag"),
            if_true="task_a",
            if_false="task_b",
        )
        ctx = WorkflowContext(workflow_id="wf1")
        ctx.set("flag", True)

        result = task.execute(ctx)
        assert result is True

    def test_condition_false(self):
        """Test conditional task with false condition."""
        task = ConditionalTask(
            condition=lambda ctx: ctx.get("flag"),
            if_true="task_a",
            if_false="task_b",
        )
        ctx = WorkflowContext(workflow_id="wf1")
        ctx.set("flag", False)

        result = task.execute(ctx)
        assert result is False


class TestParallelTask:
    """Tests for ParallelTask."""

    def test_parallel_execution(self):
        """Test parallel task execution."""
        task1 = FunctionTask(lambda ctx: "a", task_id="t1")
        task2 = FunctionTask(lambda ctx: "b", task_id="t2")

        parallel_task = ParallelTask([task1, task2], task_id="parallel")
        ctx = WorkflowContext(workflow_id="wf1")

        results = parallel_task.execute(ctx)
        assert len(results) == 2
        assert results["t1"].output == "a"
        assert results["t2"].output == "b"

    def test_parallel_with_failure(self):
        """Test parallel task with failure."""
        task1 = FunctionTask(lambda ctx: "a", task_id="t1")
        task2 = FunctionTask(
            lambda ctx: (_ for _ in ()).throw(ValueError("fail")), task_id="t2"
        )

        parallel_task = ParallelTask([task1, task2], fail_fast=False)
        ctx = WorkflowContext(workflow_id="wf1")

        results = parallel_task.execute(ctx)
        assert results["t1"].success
        assert not results["t2"].success


class TestWorkflow:
    """Tests for Workflow."""

    def test_basic_workflow(self):
        """Test basic workflow creation."""
        wf = Workflow(name="test_workflow")
        assert wf.name == "test_workflow"
        assert wf.state == WorkflowState.PENDING

    def test_add_task(self):
        """Test adding tasks to workflow."""
        wf = Workflow()
        task = FunctionTask(lambda ctx: None, task_id="t1")
        wf.add_task(task)

        assert wf.get_task("t1") == task
        assert len(wf.tasks) == 1

    def test_get_ready_tasks(self):
        """Test getting ready tasks."""
        wf = Workflow()
        t1 = FunctionTask(lambda ctx: None, task_id="t1")
        t2 = FunctionTask(lambda ctx: None, task_id="t2")
        t2.depends_on("t1")

        wf.add_task(t1)
        wf.add_task(t2)

        # Only t1 should be ready initially
        ready = wf.get_ready_tasks(set())
        assert len(ready) == 1
        assert ready[0].id == "t1"

        # After t1 completes, t2 should be ready
        ready = wf.get_ready_tasks({"t1"})
        assert len(ready) == 1
        assert ready[0].id == "t2"

    def test_execution_order(self):
        """Test topological execution order."""
        wf = Workflow()
        t1 = FunctionTask(lambda ctx: None, task_id="t1")
        t2 = FunctionTask(lambda ctx: None, task_id="t2")
        t3 = FunctionTask(lambda ctx: None, task_id="t3")

        t2.depends_on("t1")
        t3.depends_on("t2")

        wf.add_task(t1)
        wf.add_task(t2)
        wf.add_task(t3)

        order = wf.get_execution_order()
        assert order.index("t1") < order.index("t2")
        assert order.index("t2") < order.index("t3")

    def test_validate_missing_dependency(self):
        """Test validation catches missing dependencies."""
        wf = Workflow()
        task = FunctionTask(lambda ctx: None, task_id="t1")
        task.depends_on("missing")
        wf.add_task(task)

        errors = wf.validate()
        assert len(errors) > 0
        assert "missing" in errors[0]

    def test_validate_cycle_detection(self):
        """Test validation catches cycles."""
        wf = Workflow()
        t1 = FunctionTask(lambda ctx: None, task_id="t1")
        t2 = FunctionTask(lambda ctx: None, task_id="t2")

        t1.depends_on("t2")
        t2.depends_on("t1")

        wf.add_task(t1)
        wf.add_task(t2)

        errors = wf.validate()
        assert any("cycle" in e.lower() for e in errors)

    def test_to_dict(self):
        """Test workflow serialization."""
        wf = Workflow(name="test")
        wf.add_task(FunctionTask(lambda ctx: None, task_id="t1"))

        d = wf.to_dict()
        assert d["name"] == "test"
        assert "t1" in d["tasks"]


class TestWorkflowExecutor:
    """Tests for WorkflowExecutor."""

    def test_simple_execution(self):
        """Test simple workflow execution."""
        wf = Workflow()
        wf.add_task(FunctionTask(lambda ctx: ctx.set("result", 42), task_id="t1"))

        executor = WorkflowExecutor()
        ctx = executor.execute(wf)

        assert ctx.get("result") == 42
        assert wf.state == WorkflowState.COMPLETED

    def test_sequential_execution(self):
        """Test sequential task execution."""
        results = []

        def task1(ctx):
            results.append(1)
            return 1

        def task2(ctx):
            results.append(2)
            return 2

        wf = Workflow()
        t1 = FunctionTask(task1, task_id="t1")
        t2 = FunctionTask(task2, task_id="t2")
        t2.depends_on("t1")

        wf.add_task(t1)
        wf.add_task(t2)

        executor = WorkflowExecutor()
        executor.execute(wf)

        assert results == [1, 2]

    def test_parallel_execution(self):
        """Test parallel task execution."""
        executed = set()
        lock = threading.Lock()

        def make_task(name):
            def task_func(ctx):
                with lock:
                    executed.add(name)
                time.sleep(0.01)
                return name

            return task_func

        wf = Workflow()
        wf.add_task(FunctionTask(make_task("t1"), task_id="t1"))
        wf.add_task(FunctionTask(make_task("t2"), task_id="t2"))
        wf.add_task(FunctionTask(make_task("t3"), task_id="t3"))

        executor = WorkflowExecutor(max_parallel=3)
        executor.execute(wf)

        assert executed == {"t1", "t2", "t3"}

    def test_task_failure(self):
        """Test handling of task failure."""

        def failing_task(ctx):
            raise ValueError("intentional failure")

        wf = Workflow()
        wf.add_task(FunctionTask(failing_task, task_id="t1"))

        executor = WorkflowExecutor()
        ctx = executor.execute(wf)

        assert wf.state == WorkflowState.FAILED
        assert ctx.get_result("t1").state == TaskState.FAILED

    def test_task_retry(self):
        """Test task retry on failure."""
        attempts = [0]

        def flaky_task(ctx):
            attempts[0] += 1
            if attempts[0] < 3:
                raise ValueError("not yet")
            return "success"

        wf = Workflow()
        wf.add_task(FunctionTask(flaky_task, task_id="t1", retries=3))

        executor = WorkflowExecutor()
        ctx = executor.execute(wf)

        assert ctx.get_result("t1").success
        assert attempts[0] == 3

    def test_skip_dependents_on_failure(self):
        """Test that dependent tasks are skipped on failure."""

        def failing(ctx):
            raise ValueError("fail")

        wf = Workflow()
        t1 = FunctionTask(failing, task_id="t1")
        t2 = FunctionTask(lambda ctx: "ok", task_id="t2")
        t2.depends_on("t1")

        wf.add_task(t1)
        wf.add_task(t2)

        executor = WorkflowExecutor()
        ctx = executor.execute(wf)

        assert ctx.get_result("t2").state == TaskState.SKIPPED

    def test_callbacks(self):
        """Test executor callbacks."""
        started = []
        completed = []

        def on_start(task):
            started.append(task.id)

        def on_complete(task, result):
            completed.append((task.id, result.success))

        wf = Workflow()
        wf.add_task(FunctionTask(lambda ctx: None, task_id="t1"))

        executor = WorkflowExecutor(
            on_task_start=on_start,
            on_task_complete=on_complete,
        )
        executor.execute(wf)

        assert "t1" in started
        assert ("t1", True) in completed


class TestStateMachine:
    """Tests for StateMachine."""

    def test_basic_transitions(self):
        """Test basic state transitions."""
        sm = StateMachine(name="test")
        sm.set_initial_state("idle")
        sm.add_transition("idle", "running", "start")
        sm.add_transition("running", "idle", "stop")

        assert sm.current_state == "idle"

        sm.trigger("start")
        assert sm.current_state == "running"

        sm.trigger("stop")
        assert sm.current_state == "idle"

    def test_conditional_transition(self):
        """Test conditional transitions."""
        sm = StateMachine()
        sm.set_initial_state("pending")
        sm.add_transition(
            "pending",
            "approved",
            "review",
            condition=lambda ctx: ctx.get("score", 0) >= 70,
        )
        sm.add_transition(
            "pending",
            "rejected",
            "review",
            condition=lambda ctx: ctx.get("score", 0) < 70,
        )

        sm.trigger("review", score=80)
        assert sm.current_state == "approved"

    def test_transition_action(self):
        """Test transition actions."""
        actions_called = []

        def my_action(ctx):
            actions_called.append("action")
            ctx["processed"] = True

        sm = StateMachine()
        sm.set_initial_state("start")
        sm.add_transition("start", "end", "go", action=my_action)

        sm.trigger("go")
        assert "action" in actions_called
        assert sm.context.get("processed") is True

    def test_state_handler(self):
        """Test state entry handlers."""
        entered = []

        def on_enter_running(ctx):
            entered.append("running")

        sm = StateMachine()
        sm.set_initial_state("idle")
        sm.add_transition("idle", "running", "start")
        sm.set_state_handler("running", on_enter_running)

        sm.trigger("start")
        assert "running" in entered

    def test_can_trigger(self):
        """Test checking if event can be triggered."""
        sm = StateMachine()
        sm.set_initial_state("idle")
        sm.add_transition("idle", "running", "start")

        assert sm.can_trigger("start")
        assert not sm.can_trigger("stop")

    def test_history(self):
        """Test transition history."""
        sm = StateMachine()
        sm.set_initial_state("a")
        sm.add_transition("a", "b", "go")
        sm.add_transition("b", "c", "go")

        sm.trigger("go")
        sm.trigger("go")

        history = sm.history
        assert len(history) == 2
        assert history[0] == ("a", "go", "b")
        assert history[1] == ("b", "go", "c")

    def test_final_state(self):
        """Test final state detection."""
        sm = StateMachine()
        sm.add_state("start")
        sm.add_state("end", is_final=True)
        sm.set_initial_state("start")
        sm.add_transition("start", "end", "finish")

        assert not sm.is_final()
        sm.trigger("finish")
        assert sm.is_final()

    def test_reset(self):
        """Test state machine reset."""
        sm = StateMachine()
        sm.set_initial_state("start")
        sm.add_transition("start", "end", "go")

        sm.trigger("go")
        assert sm.current_state == "end"

        sm.reset()
        assert sm.current_state == "start"
        assert len(sm.history) == 0

    def test_available_events(self):
        """Test getting available events."""
        sm = StateMachine()
        sm.set_initial_state("idle")
        sm.add_transition("idle", "running", "start")
        sm.add_transition("idle", "stopped", "stop")
        sm.add_transition("running", "idle", "pause")

        events = sm.get_available_events()
        assert "start" in events
        assert "stop" in events
        assert "pause" not in events

    def test_to_dict(self):
        """Test state machine serialization."""
        sm = StateMachine(name="test_sm")
        sm.set_initial_state("idle")
        sm.add_transition("idle", "running", "start")

        d = sm.to_dict()
        assert d["name"] == "test_sm"
        assert d["current_state"] == "idle"
        assert len(d["transitions"]) == 1


class TestWorkflowBuilder:
    """Tests for WorkflowBuilder."""

    def test_basic_builder(self):
        """Test basic workflow builder usage."""
        wf = (
            WorkflowBuilder("my_workflow")
            .add_task(lambda ctx: 1, task_id="t1")
            .add_task(lambda ctx: 2, task_id="t2")
            .depends_on("t1")
            .build()
        )

        assert wf.name == "my_workflow"
        assert len(wf.tasks) == 2
        assert "t1" in wf.get_task("t2").dependencies

    def test_builder_with_conditional(self):
        """Test builder with conditional task."""
        wf = (
            WorkflowBuilder()
            .add_conditional(
                condition=lambda ctx: True,
                if_true="branch_a",
                task_id="check",
            )
            .build()
        )

        task = wf.get_task("check")
        assert isinstance(task, ConditionalTask)

    def test_builder_with_parallel(self):
        """Test builder with parallel task."""
        subtasks = [
            FunctionTask(lambda ctx: "a", task_id="a"),
            FunctionTask(lambda ctx: "b", task_id="b"),
        ]

        wf = WorkflowBuilder().add_parallel(subtasks, task_id="parallel").build()

        task = wf.get_task("parallel")
        assert isinstance(task, ParallelTask)


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_workflow_function(self):
        """Test workflow() convenience function."""
        builder = workflow("test")
        assert isinstance(builder, WorkflowBuilder)

    def test_task_function(self):
        """Test task() convenience function."""
        t = task(lambda ctx: None, task_id="t1")
        assert isinstance(t, FunctionTask)
        assert t.id == "t1"

    def test_parallel_function(self):
        """Test parallel() convenience function."""
        t1 = task(lambda ctx: None)
        t2 = task(lambda ctx: None)
        p = parallel(t1, t2)

        assert isinstance(p, ParallelTask)
        assert len(p.tasks) == 2

    def test_conditional_function(self):
        """Test conditional() convenience function."""
        c = conditional(lambda ctx: True, if_true="a", if_false="b")
        assert isinstance(c, ConditionalTask)


class TestSubWorkflowTask:
    """Tests for SubWorkflowTask."""

    def test_sub_workflow_execution(self):
        """Test sub-workflow execution."""
        # Create sub-workflow
        sub_wf = Workflow(name="sub")
        sub_wf.add_task(
            FunctionTask(
                lambda ctx: ctx.set("sub_result", "from_sub"), task_id="sub_t1"
            )
        )

        # Create main workflow with sub-workflow task
        main_wf = Workflow(name="main")
        main_wf.add_task(SubWorkflowTask(sub_wf, task_id="run_sub"))

        executor = WorkflowExecutor()
        ctx = executor.execute(main_wf)

        # Sub-workflow result should be in main context
        sub_ctx = ctx.get_output("run_sub")
        assert sub_ctx.get("sub_result") == "from_sub"


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_state_machine_transitions(self):
        """Test concurrent state machine transitions."""
        sm = StateMachine()
        sm.set_initial_state("count_0")
        for i in range(100):
            sm.add_transition(f"count_{i}", f"count_{i + 1}", "increment")

        def increment_many():
            for _ in range(10):
                sm.trigger("increment")

        threads = [threading.Thread(target=increment_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Final state should be count_100
        assert sm.current_state == "count_100"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_workflow(self):
        """Test executing empty workflow."""
        wf = Workflow()
        executor = WorkflowExecutor()
        executor.execute(wf)

        assert wf.state == WorkflowState.COMPLETED

    def test_single_task_workflow(self):
        """Test single task workflow."""
        wf = Workflow()
        wf.add_task(FunctionTask(lambda ctx: "done", task_id="only"))

        executor = WorkflowExecutor()
        ctx = executor.execute(wf)

        assert ctx.get_output("only") == "done"

    def test_diamond_dependency(self):
        """Test diamond dependency pattern."""
        #     t1
        #    /  \
        #   t2   t3
        #    \  /
        #     t4

        wf = Workflow()
        t1 = FunctionTask(lambda ctx: ctx.set("t1", True), task_id="t1")
        t2 = FunctionTask(lambda ctx: ctx.set("t2", True), task_id="t2")
        t3 = FunctionTask(lambda ctx: ctx.set("t3", True), task_id="t3")
        t4 = FunctionTask(lambda ctx: ctx.set("t4", True), task_id="t4")

        t2.depends_on("t1")
        t3.depends_on("t1")
        t4.depends_on("t2", "t3")

        wf.add_task(t1)
        wf.add_task(t2)
        wf.add_task(t3)
        wf.add_task(t4)

        executor = WorkflowExecutor()
        ctx = executor.execute(wf)

        assert ctx.get("t4") is True
        assert wf.state == WorkflowState.COMPLETED

    def test_invalid_event_trigger(self):
        """Test triggering invalid event."""
        sm = StateMachine()
        sm.set_initial_state("idle")

        result = sm.trigger("nonexistent")
        assert result is False
        assert sm.current_state == "idle"
