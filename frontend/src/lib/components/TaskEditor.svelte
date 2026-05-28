<script>
  import { LoaderCircle, Save, X } from "lucide-svelte";
  import { STATUS_OPTIONS } from "../config.js";
  import { statusLabel } from "../domain/task.js";

  export let taskMode = "create";
  /** @type {Record<string, any>} */
  export let taskForm;
  export let savingTask = false;
  export let onCancel = () => {};
  export let onFormChange = (_form) => {};
  export let onSubmit = () => {};

  function updateField(field, value) {
    onFormChange({ ...taskForm, [field]: value });
  }
</script>

<section class="tool-panel">
  <div class="panel-head">
    <div>
      <h2>{taskMode === "edit" ? "Edit task" : "Add task"}</h2>
    </div>
    {#if taskMode === "edit"}
      <button class="icon-button" type="button" on:click={onCancel} title="Cancel edit" aria-label="Cancel edit">
        <X size={18} aria-hidden="true" />
      </button>
    {/if}
  </div>

  <form class="task-form" on:submit|preventDefault={onSubmit}>
    <label>
      <span>Title</span>
      <input
        value={taskForm.title}
        required
        on:input={(event) => updateField("title", event.currentTarget.value)}
      />
    </label>
    <label>
      <span>Description</span>
      <textarea
        value={taskForm.description}
        rows="4"
        on:input={(event) => updateField("description", event.currentTarget.value)}
      ></textarea>
    </label>
    <div class="form-grid">
      <label>
        <span>Status</span>
        <select value={taskForm.status} on:change={(event) => updateField("status", event.currentTarget.value)}>
          {#each STATUS_OPTIONS as status}
            <option value={status}>{statusLabel(status)}</option>
          {/each}
        </select>
      </label>
      <label>
        <span>Due date</span>
        <input
          value={taskForm.due_date}
          type="date"
          on:input={(event) => updateField("due_date", event.currentTarget.value)}
        />
      </label>
    </div>
    <button class="button-primary full-width" type="submit" disabled={savingTask}>
      {#if savingTask}
        <LoaderCircle class="spin" size={18} aria-hidden="true" />
      {:else}
        <Save size={18} aria-hidden="true" />
      {/if}
      {taskMode === "edit" ? "Save task" : "Create task"}
    </button>
  </form>
</section>
