<script>
  import {
    Calendar,
    CheckSquare,
    Eye,
    ListChecks,
    LoaderCircle,
    Pencil,
    Plus,
    Search,
    Square,
    Trash2
  } from "lucide-svelte";
  import { STATUS_OPTIONS } from "../config.js";
  import { formatTaskDate, formatTimestamp, statusClass, statusLabel } from "../domain/task.js";

  /** @type {Array<Record<string, any>>} */
  export let filteredTasks = [];
  /** @type {Record<string, number>} */
  export let taskCounts = {};
  /** @type {Record<string, any> | null} */
  export let selectedTask = null;
  export let searchTerm = "";
  export let statusFilter = "ALL";
  export let loadingTasks = false;
  export let visibleIncompleteCount = 0;
  export let onSearchChange = (_value) => {};
  export let onStatusFilterChange = (_status) => {};
  export let onCreate = () => {};
  export let onCheckAll = () => {};
  export let onView = (_task) => {};
  export let onEdit = (_task) => {};
  export let onDelete = (_task) => {};
  export let onToggle = (_task) => {};

  function handleTaskKey(event, task) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onView(task);
    }
  }
</script>

<section class="task-column">
  <div class="section-head">
    <div>
      <h1>Tasks</h1>
    </div>
    <div class="head-actions">
      <button
        class="button-outline"
        type="button"
        on:click={onCheckAll}
        disabled={visibleIncompleteCount === 0}
      >
        <CheckSquare size={18} aria-hidden="true" />
        Complete all
      </button>
      <button class="button-primary" type="button" on:click={onCreate}>
        <Plus size={18} aria-hidden="true" />
        Add task
      </button>
    </div>
  </div>

  <div class="toolbar">
    <label class="search-field">
      <Search size={18} aria-hidden="true" />
      <input
        value={searchTerm}
        placeholder="Search tasks"
        on:input={(event) => onSearchChange(event.currentTarget.value)}
      />
    </label>

    <div class="filter-tabs" aria-label="Task status filter">
      {#each ["ALL", ...STATUS_OPTIONS] as status}
        <button
          type="button"
          class:active={statusFilter === status}
          on:click={() => onStatusFilterChange(status)}
        >
          {status === "ALL" ? "All" : statusLabel(status)}
          <span>{taskCounts[status] || 0}</span>
        </button>
      {/each}
    </div>
  </div>

  <div class="stats-strip" aria-label="Task counts">
    <div>
      <span>Total</span>
      <strong>{taskCounts.ALL || 0}</strong>
    </div>
    <div>
      <span>Pending</span>
      <strong>{taskCounts.PENDING || 0}</strong>
    </div>
    <div>
      <span>In progress</span>
      <strong>{taskCounts.IN_PROGRESS || 0}</strong>
    </div>
    <div>
      <span>Completed</span>
      <strong>{taskCounts.COMPLETED || 0}</strong>
    </div>
  </div>

  <div class="task-list" aria-live="polite">
    {#if loadingTasks}
      <div class="empty-state">
        <LoaderCircle class="spin" size={22} aria-hidden="true" />
        Loading tasks
      </div>
    {:else if filteredTasks.length === 0}
      <div class="empty-state">
        <ListChecks size={22} aria-hidden="true" />
        No tasks found
      </div>
    {:else}
      {#each filteredTasks as task (task.id)}
        <article class="task-row" class:selected={selectedTask?.id === task.id}>
          <button
            class="check-button"
            type="button"
            on:click={() => onToggle(task)}
            title={task.status === "COMPLETED" ? "Reopen task" : "Check task"}
            aria-label={task.status === "COMPLETED" ? "Reopen task" : "Check task"}
          >
            {#if task.status === "COMPLETED"}
              <CheckSquare size={22} aria-hidden="true" />
            {:else}
              <Square size={22} aria-hidden="true" />
            {/if}
          </button>

          <div
            class="task-main"
            role="button"
            tabindex="0"
            on:click={() => onView(task)}
            on:keydown={(event) => handleTaskKey(event, task)}
          >
            <div class="task-title-row">
              <h2>{task.title}</h2>
              <span class={`status-badge ${statusClass(task.status)}`}>{statusLabel(task.status)}</span>
            </div>
            {#if task.description}
              <p>{task.description}</p>
            {/if}
            <div class="meta-row">
              <span>
                <Calendar size={14} aria-hidden="true" />
                {formatTaskDate(task.due_date)}
              </span>
              <span>Updated {formatTimestamp(task.updated_at)}</span>
            </div>
          </div>

          <div class="row-actions">
            <button
              class="icon-button"
              type="button"
              on:click={() => onView(task)}
              title="View task"
              aria-label="View task"
            >
              <Eye size={17} aria-hidden="true" />
            </button>
            <button
              class="icon-button"
              type="button"
              on:click={() => onEdit(task)}
              title="Edit task"
              aria-label="Edit task"
            >
              <Pencil size={17} aria-hidden="true" />
            </button>
            <button
              class="icon-button danger"
              type="button"
              on:click={() => onDelete(task)}
              title="Delete task"
              aria-label="Delete task"
            >
              <Trash2 size={17} aria-hidden="true" />
            </button>
          </div>
        </article>
      {/each}
    {/if}
  </div>
</section>
