<script>
  import { onMount } from "svelte";
  import {
    Calendar,
    CheckSquare,
    Eye,
    ListChecks,
    LoaderCircle,
    LogIn,
    LogOut,
    Pencil,
    Plus,
    Save,
    Search,
    Square,
    Trash2,
    User,
    X
  } from "lucide-svelte";
  import { ApiError, request } from "./lib/api.js";
  import { decodeJwt } from "./lib/token.js";

  const STORAGE_KEY = "tasktify.session";
  const DEFAULT_ALGORITHM = "Falcon-Precomputed-512";

  const statusOptions = ["PENDING", "IN_PROGRESS", "COMPLETED"];

  let bootstrapping = true;
  let authMode = "signin";
  let authForm = {
    name: "",
    email: "",
    password: ""
  };
  let session = emptySession();
  let profile = null;
  let tasks = [];
  let selectedTask = null;
  let taskMode = "create";
  let taskForm = emptyTaskForm();
  let searchTerm = "";
  let statusFilter = "ALL";
  let loadingAuth = false;
  let loadingTasks = false;
  let savingTask = false;
  let errorMessage = "";
  let noticeMessage = "";
  let noticeTimer;

  $: authenticated = Boolean(session.access_token);
  $: accessJwt = decodeJwt(session.access_token);
  $: filteredTasks = tasks.filter((task) => matchesTask(task, searchTerm, statusFilter));
  $: taskCounts = buildTaskCounts(tasks);
  $: visibleIncompleteCount = filteredTasks.filter((task) => task.status !== "COMPLETED").length;

  onMount(async () => {
    session = readStoredSession();
    if (session.access_token) {
      await bootstrapSession();
    }
    bootstrapping = false;
  });

  function emptySession() {
    return {
      token_type: "Bearer",
      access_token: "",
      refresh_token: "",
      saved_at: ""
    };
  }

  function emptyTaskForm() {
    return {
      id: "",
      title: "",
      description: "",
      status: "PENDING",
      due_date: ""
    };
  }

  function readStoredSession() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? { ...emptySession(), ...JSON.parse(stored) } : emptySession();
    } catch {
      return emptySession();
    }
  }

  function writeSession(nextSession) {
    session = { ...emptySession(), ...nextSession };
    if (session.access_token && session.refresh_token) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }

  function clearSession() {
    writeSession(emptySession());
    profile = null;
    tasks = [];
    selectedTask = null;
    taskForm = emptyTaskForm();
  }

  async function bootstrapSession() {
    try {
      await Promise.all([loadProfile(), loadTasks()]);
    } catch (error) {
      handleError(error);
    }
  }

  async function handleAuthSubmit() {
    clearMessages();
    loadingAuth = true;
    try {
      if (authMode === "register") {
        await request("/api/auth/register", {
          method: "POST",
          body: {
            name: authForm.name.trim(),
            email: authForm.email.trim(),
            password: authForm.password
          }
        });
      }

      const { payload } = await request("/api/auth/signin", {
        method: "POST",
        body: {
          email: authForm.email.trim(),
          password: authForm.password,
          algorithm: DEFAULT_ALGORITHM
        }
      });

      writeSession({
        ...emptySession(),
        ...(payload?.data || {}),
        saved_at: new Date().toISOString()
      });

      await bootstrapSession();
      taskMode = "create";
      taskForm = emptyTaskForm();
      showNotice(authMode === "register" ? "Account created" : "Signed in");
    } catch (error) {
      handleError(error);
    } finally {
      loadingAuth = false;
    }
  }

  async function authedRequest(path, options = {}, retry = true) {
    try {
      return await request(path, {
        ...options,
        token: session.access_token
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401 && retry && session.refresh_token) {
        await refreshSession();
        return authedRequest(path, options, false);
      }
      throw error;
    }
  }

  async function refreshSession() {
    clearMessages();
    try {
      const decodedRefresh = decodeJwt(session.refresh_token);
      const decodedAccess = decodeJwt(session.access_token);
      const userId = decodedRefresh?.payload?.user_id || decodedAccess?.payload?.user_id || "";
      const { payload } = await request("/api/auth/refresh", {
        method: "POST",
        body: {
          user_id: userId,
          refresh_token: session.refresh_token
        }
      });

      writeSession({
        ...session,
        ...(payload?.data || {}),
        saved_at: new Date().toISOString()
      });
    } catch (error) {
      clearSession();
      handleError(error);
    }
  }

  function logout() {
    clearMessages();
    clearSession();
    showNotice("Signed out");
  }

  async function loadProfile() {
    const { payload } = await authedRequest("/api/profile");
    profile = payload?.data || null;
  }

  async function loadTasks() {
    loadingTasks = true;
    try {
      const { payload } = await authedRequest("/api/tasks/");
      tasks = (payload?.data || []).map(normalizeTask);
      if (selectedTask) {
        selectedTask = tasks.find((task) => task.id === selectedTask.id) || null;
      }
    } finally {
      loadingTasks = false;
    }
  }

  async function viewTask(task) {
    clearMessages();
    try {
      const { payload } = await authedRequest(`/api/tasks/${task.id}`);
      selectedTask = normalizeTask(payload?.data || task);
    } catch (error) {
      handleError(error);
    }
  }

  function handleTaskKey(event, task) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      viewTask(task);
    }
  }

  function startCreateTask() {
    clearMessages();
    taskMode = "create";
    selectedTask = null;
    taskForm = emptyTaskForm();
  }

  function startEditTask(task) {
    clearMessages();
    taskMode = "edit";
    selectedTask = task;
    taskForm = {
      id: task.id,
      title: task.title,
      description: task.description,
      status: task.status || "PENDING",
      due_date: toDateInput(task.due_date)
    };
  }

  async function saveTask() {
    clearMessages();
    if (!taskForm.title.trim()) {
      errorMessage = "Task title required";
      return;
    }

    savingTask = true;
    try {
      const body = taskFormPayload(taskForm);
      const successMessage = taskMode === "edit" && taskForm.id ? "Task updated" : "Task added";
      if (taskMode === "edit" && taskForm.id) {
        await authedRequest(`/api/tasks/${taskForm.id}`, {
          method: "PUT",
          body
        });
      } else {
        await authedRequest("/api/tasks/", {
          method: "POST",
          body
        });
      }

      await loadTasks();
      taskMode = "create";
      selectedTask = null;
      taskForm = emptyTaskForm();
      showNotice(successMessage);
    } catch (error) {
      handleError(error);
    } finally {
      savingTask = false;
    }
  }

  async function deleteTask(task) {
    if (!confirm(`Delete "${task.title}"?`)) {
      return;
    }

    clearMessages();
    try {
      await authedRequest(`/api/tasks/${task.id}`, {
        method: "DELETE"
      });
      if (selectedTask?.id === task.id) {
        selectedTask = null;
      }
      await loadTasks();
      showNotice("Task deleted");
    } catch (error) {
      handleError(error);
    }
  }

  async function toggleTask(task) {
    const nextStatus = task.status === "COMPLETED" ? "PENDING" : "COMPLETED";
    clearMessages();
    try {
      await updateTaskStatus(task, nextStatus);
      showNotice(nextStatus === "COMPLETED" ? "Task checked" : "Task reopened");
    } catch (error) {
      handleError(error);
    }
  }

  async function checkAllVisibleTasks() {
    const targets = filteredTasks.filter((task) => task.status !== "COMPLETED");
    if (targets.length === 0) {
      return;
    }

    clearMessages();
    try {
      await Promise.all(targets.map((task) => updateTaskStatus(task, "COMPLETED", false)));
      await loadTasks();
      showNotice("Visible tasks checked");
    } catch (error) {
      handleError(error);
    }
  }

  async function updateTaskStatus(task, status, reload = true) {
    await authedRequest(`/api/tasks/${task.id}`, {
      method: "PUT",
      body: taskPayload({ ...task, status })
    });

    if (reload) {
      await loadTasks();
    }
  }

  function taskFormPayload(form) {
    return {
      title: form.title.trim(),
      description: form.description.trim(),
      status: form.status,
      due_date: dateInputToMs(form.due_date)
    };
  }

  function taskPayload(task) {
    return {
      title: task.title,
      description: task.description || "",
      status: task.status || "PENDING",
      due_date: task.due_date || 0
    };
  }

  function normalizeTask(task) {
    return {
      id: task.id || "",
      title: task.title || "",
      description: task.description || "",
      status: task.status || "PENDING",
      due_date: Number(task.due_date || 0),
      user_id: task.user_id || "",
      created_at: Number(task.created_at || 0),
      updated_at: Number(task.updated_at || 0)
    };
  }

  function matchesTask(task, query, filter) {
    const statusMatch = filter === "ALL" || task.status === filter;
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) {
      return statusMatch;
    }

    const text = `${task.title} ${task.description} ${task.status}`.toLowerCase();
    return statusMatch && text.includes(normalizedQuery);
  }

  function buildTaskCounts(sourceTasks) {
    return {
      ALL: sourceTasks.length,
      PENDING: sourceTasks.filter((task) => task.status === "PENDING").length,
      IN_PROGRESS: sourceTasks.filter((task) => task.status === "IN_PROGRESS").length,
      COMPLETED: sourceTasks.filter((task) => task.status === "COMPLETED").length
    };
  }

  function handleError(error) {
    if (error instanceof ApiError) {
      errorMessage = error.message;
      return;
    }
    errorMessage = error?.message || "Request failed";
  }

  function clearMessages() {
    errorMessage = "";
    noticeMessage = "";
  }

  function showNotice(message) {
    noticeMessage = message;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => {
      noticeMessage = "";
    }, 3500);
  }

  function statusLabel(status) {
    if (status === "IN_PROGRESS") {
      return "In progress";
    }
    if (status === "COMPLETED") {
      return "Completed";
    }
    return "Pending";
  }

  function statusClass(status) {
    return status.toLowerCase().replace("_", "-");
  }

  function dateInputToMs(value) {
    if (!value) {
      return 0;
    }
    return new Date(`${value}T00:00:00`).getTime();
  }

  function toDateInput(ms) {
    if (!ms) {
      return "";
    }
    const date = new Date(ms);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  }

  function formatTaskDate(ms) {
    if (!ms) {
      return "No due date";
    }
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium"
    }).format(new Date(ms));
  }

  function formatTimestamp(ms) {
    if (!ms) {
      return "-";
    }
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(new Date(ms));
  }
</script>

{#if bootstrapping}
  <main class="loading-page">
    <span class="brand-mark" aria-hidden="true"></span>
    <LoaderCircle class="spin" size={28} aria-hidden="true" />
  </main>
{:else if !authenticated}
  <main class="auth-page">
    <section class="auth-panel">
      <div class="auth-card">
        <div class="auth-brand">
          <div class="brand-row">
            <span class="brand-mark" aria-hidden="true"></span>
            <span>Tasktify</span>
          </div>
        </div>

        <h1>{authMode === "register" ? "Create account" : "Welcome back"}</h1>

        <div class="segmented" aria-label="Authentication mode">
          <button
            type="button"
            class:active={authMode === "signin"}
            on:click={() => (authMode = "signin")}
          >
            Sign in
          </button>
          <button
            type="button"
            class:active={authMode === "register"}
            on:click={() => (authMode = "register")}
          >
            Register
          </button>
        </div>

        <form class="auth-form" on:submit|preventDefault={handleAuthSubmit}>
          {#if authMode === "register"}
            <label>
              <span>Name</span>
              <input bind:value={authForm.name} autocomplete="name" required />
            </label>
          {/if}

          <label>
            <span>Email</span>
            <input bind:value={authForm.email} type="email" autocomplete="email" required />
          </label>

          <label>
            <span>Password</span>
            <input
              bind:value={authForm.password}
              type="password"
              autocomplete={authMode === "register" ? "new-password" : "current-password"}
              minlength="6"
              required
            />
          </label>

          {#if errorMessage}
            <p class="form-error">{errorMessage}</p>
          {/if}
          {#if noticeMessage}
            <p class="form-notice">{noticeMessage}</p>
          {/if}

          <button class="button-primary" type="submit" disabled={loadingAuth}>
            {#if loadingAuth}
              <LoaderCircle class="spin" size={18} aria-hidden="true" />
            {:else}
              <LogIn size={18} aria-hidden="true" />
            {/if}
            {authMode === "register" ? "Create account" : "Sign in"}
          </button>
        </form>
      </div>
    </section>
  </main>
{:else}
  <div class="app-shell">
    <header class="topbar">
      <div class="brand-row">
        <span class="brand-mark" aria-hidden="true"></span>
        <span>Tasktify</span>
      </div>

      <div class="topbar-actions">
        <button class="icon-button on-dark" type="button" on:click={logout} title="Logout" aria-label="Logout">
          <LogOut size={18} aria-hidden="true" />
        </button>
      </div>
    </header>

    {#if errorMessage || noticeMessage}
      <div class="message-bar" class:error={Boolean(errorMessage)}>
        {errorMessage || noticeMessage}
      </div>
    {/if}

    <main class="workspace">
      <section class="task-column">
        <div class="section-head">
          <div>
            <h1>Tasks</h1>
          </div>
          <div class="head-actions">
            <button class="button-outline" type="button" on:click={checkAllVisibleTasks} disabled={visibleIncompleteCount === 0}>
              <CheckSquare size={18} aria-hidden="true" />
              Complete all
            </button>
            <button class="button-primary" type="button" on:click={startCreateTask}>
              <Plus size={18} aria-hidden="true" />
              Add task
            </button>
          </div>
        </div>

        <div class="toolbar">
          <label class="search-field">
            <Search size={18} aria-hidden="true" />
            <input bind:value={searchTerm} placeholder="Search tasks" />
          </label>

          <div class="filter-tabs" aria-label="Task status filter">
            {#each ["ALL", ...statusOptions] as status}
              <button
                type="button"
                class:active={statusFilter === status}
                on:click={() => (statusFilter = status)}
              >
                {status === "ALL" ? "All" : statusLabel(status)}
                <span>{taskCounts[status]}</span>
              </button>
            {/each}
          </div>
        </div>

        <div class="stats-strip" aria-label="Task counts">
          <div>
            <span>Total</span>
            <strong>{taskCounts.ALL}</strong>
          </div>
          <div>
            <span>Pending</span>
            <strong>{taskCounts.PENDING}</strong>
          </div>
          <div>
            <span>In progress</span>
            <strong>{taskCounts.IN_PROGRESS}</strong>
          </div>
          <div>
            <span>Completed</span>
            <strong>{taskCounts.COMPLETED}</strong>
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
                  on:click={() => toggleTask(task)}
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
                  on:click={() => viewTask(task)}
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
                  <button class="icon-button" type="button" on:click={() => viewTask(task)} title="View task" aria-label="View task">
                    <Eye size={17} aria-hidden="true" />
                  </button>
                  <button class="icon-button" type="button" on:click={() => startEditTask(task)} title="Edit task" aria-label="Edit task">
                    <Pencil size={17} aria-hidden="true" />
                  </button>
                  <button class="icon-button danger" type="button" on:click={() => deleteTask(task)} title="Delete task" aria-label="Delete task">
                    <Trash2 size={17} aria-hidden="true" />
                  </button>
                </div>
              </article>
            {/each}
          {/if}
        </div>
      </section>

      <aside class="side-column">
        <section class="tool-panel">
          <div class="panel-head">
            <div>
              <h2>{taskMode === "edit" ? "Edit task" : "Add task"}</h2>
            </div>
            {#if taskMode === "edit"}
              <button class="icon-button" type="button" on:click={startCreateTask} title="Cancel edit" aria-label="Cancel edit">
                <X size={18} aria-hidden="true" />
              </button>
            {/if}
          </div>

          <form class="task-form" on:submit|preventDefault={saveTask}>
            <label>
              <span>Title</span>
              <input bind:value={taskForm.title} required />
            </label>
            <label>
              <span>Description</span>
              <textarea bind:value={taskForm.description} rows="4"></textarea>
            </label>
            <div class="form-grid">
              <label>
                <span>Status</span>
                <select bind:value={taskForm.status}>
                  {#each statusOptions as status}
                    <option value={status}>{statusLabel(status)}</option>
                  {/each}
                </select>
              </label>
              <label>
                <span>Due date</span>
                <input bind:value={taskForm.due_date} type="date" />
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

        <section class="tool-panel">
          <div class="panel-head">
            <div>
              <h2>Profile</h2>
            </div>
            <User size={20} aria-hidden="true" />
          </div>

          <dl class="detail-list compact">
            <div>
              <dt>Name</dt>
              <dd>{profile?.name || "-"}</dd>
            </div>
            <div>
              <dt>Email</dt>
              <dd>{profile?.email || accessJwt?.payload?.email || "-"}</dd>
            </div>
            <div>
              <dt>Security</dt>
              <dd>Falcon Precomputed 512</dd>
            </div>
          </dl>
        </section>
      </aside>
    </main>
  </div>
{/if}
