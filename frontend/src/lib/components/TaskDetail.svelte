<script>
  import { formatTaskDate, formatTimestamp, statusLabel } from "../domain/task.js";

  /** @type {Record<string, any> | null} */
  export let selectedTask = null;
</script>

<section class="tool-panel">
  <div class="panel-head">
    <div>
      <h2>Task detail</h2>
    </div>
  </div>

  {#if selectedTask}
    <dl class="detail-list">
      <div>
        <dt>Title</dt>
        <dd>{selectedTask.title}</dd>
      </div>
      <div>
        <dt>Status</dt>
        <dd>{statusLabel(selectedTask.status)}</dd>
      </div>
      <div>
        <dt>Description</dt>
        <dd>{selectedTask.description || "-"}</dd>
      </div>
      <div>
        <dt>Due date</dt>
        <dd>{formatTaskDate(selectedTask.due_date)}</dd>
      </div>
      <div>
        <dt>Created</dt>
        <dd>{formatTimestamp(selectedTask.created_at)}</dd>
      </div>
      <div>
        <dt>Updated</dt>
        <dd>{formatTimestamp(selectedTask.updated_at)}</dd>
      </div>
    </dl>
  {:else}
    <p class="muted-text">No task selected</p>
  {/if}
</section>
