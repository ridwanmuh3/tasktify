<script>
  import { onMount, tick } from "svelte";
  import { ListChecks, LoaderCircle, LogOut, User } from "lucide-svelte";
  import AuthView from "./lib/components/AuthView.svelte";
  import ProfilePage from "./lib/components/ProfilePage.svelte";
  import TaskBoard from "./lib/components/TaskBoard.svelte";
  import TaskDetail from "./lib/components/TaskDetail.svelte";
  import TaskEditor from "./lib/components/TaskEditor.svelte";
  import { ApiError, request } from "./lib/api.js";
  import {
    canUseSession,
    emptySession,
    normalizeSession,
    persistSession,
    readStoredSession,
    shouldRefreshAccessToken
  } from "./lib/domain/session.js";
  import {
    buildTaskCounts,
    emptyTaskForm,
    matchesTask,
    taskFormPayload,
    toDateInput
  } from "./lib/domain/task.js";
  import { getProfile, refresh, register, signIn } from "./lib/services/authService.js";
  import {
    createTask,
    deleteTask as removeTask,
    getTask,
    listTasks,
    updateTask,
    updateTaskStatus
  } from "./lib/services/taskService.js";
  import { decodeJwt } from "./lib/token.js";

  let bootstrapping = true;
  /** @type {"signin" | "register"} */
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
  let taskEditorOpen = false;
  let taskForm = emptyTaskForm();
  let searchTerm = "";
  let statusFilter = "ALL";
  let currentPage = "tasks";
  let loadingAuth = false;
  let loadingTasks = false;
  let savingTask = false;
  let errorMessage = "";
  let noticeMessage = "";
  let noticeTimer;
  let refreshPromise = null;

  const SESSION_EXPIRED_MESSAGE = "Session expired. Sign in again.";

  $: authenticated = Boolean(session.access_token && session.refresh_token);
  $: accessJwt = decodeJwt(session.access_token);
  $: filteredTasks = tasks.filter((task) => matchesTask(task, searchTerm, statusFilter));
  $: taskCounts = buildTaskCounts(tasks);
  $: visibleIncompleteCount = filteredTasks.filter((task) => task.status !== "COMPLETED").length;

  onMount(() => {
    const syncPage = () => {
      currentPage = pageFromHash(window.location.hash);
    };

    syncPage();
    window.addEventListener("hashchange", syncPage);

    const bootstrap = async () => {
      const storedSession = readStoredSession();
      if (canUseSession(storedSession)) {
        session = storedSession;
        await bootstrapSession();
      } else {
        clearSession();
      }
      bootstrapping = false;
    };

    bootstrap();

    return () => {
      window.removeEventListener("hashchange", syncPage);
    };
  });

  function setSession(nextSession) {
    session = persistSession(normalizeSession(nextSession));
  }

  function clearSession() {
    setSession(emptySession());
    profile = null;
    tasks = [];
    selectedTask = null;
    taskEditorOpen = false;
    taskForm = emptyTaskForm();
  }

  async function bootstrapSession() {
    try {
      if (shouldRefreshAccessToken(session)) {
        await refreshSession();
      }
      await loadProfile();
      await loadTasks();
      return true;
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        clearSession();
        error = sessionExpiredError(error);
      }
      handleError(error);
      return false;
    }
  }

  async function handleAuthSubmit() {
    clearMessages();
    loadingAuth = true;
    try {
      if (authMode === "register") {
        await register(authForm);
      }

      setSession({
        ...emptySession(),
        ...(await signIn(authForm)),
        saved_at: new Date().toISOString()
      });

      if (!(await bootstrapSession())) {
        return;
      }
      taskMode = "create";
      taskEditorOpen = false;
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
      if (error instanceof ApiError && error.status === 401 && retry && canUseSession(session)) {
        await refreshSession();
        return authedRequest(path, options, false);
      }
      if (error instanceof ApiError && error.status === 401) {
        clearSession();
        throw sessionExpiredError(error);
      }
      throw error;
    }
  }

  async function refreshSession() {
    if (!refreshPromise) {
      refreshPromise = refresh(session)
        .then((nextSession) => {
          setSession({
            ...session,
            ...nextSession,
            saved_at: new Date().toISOString()
          });
        })
        .catch((error) => {
          if (isSessionAuthError(error)) {
            clearSession();
            throw sessionExpiredError(error);
          }
          throw error;
        })
        .finally(() => {
          refreshPromise = null;
        });
    }
    return refreshPromise;
  }

  function sessionExpiredError(error) {
    return new ApiError(
      SESSION_EXPIRED_MESSAGE,
      401,
      error instanceof ApiError ? error.payload : null
    );
  }

  function isSessionAuthError(error) {
    return error instanceof ApiError && [400, 401, 404].includes(error.status);
  }

  function logout() {
    clearMessages();
    clearSession();
    showNotice("Signed out");
  }

  function navigatePage(page) {
    currentPage = page;
    window.location.hash = page === "profile" ? "profile" : "tasks";
  }

  function pageFromHash(hash) {
    return hash.replace(/^#\/?/, "") === "profile" ? "profile" : "tasks";
  }

  async function loadProfile() {
    profile = await getProfile(authedRequest);
  }

  async function loadTasks() {
    loadingTasks = true;
    try {
      tasks = await listTasks(authedRequest);
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
      selectedTask = await getTask(authedRequest, task);
    } catch (error) {
      handleError(error);
    }
  }

  function startCreateTask() {
    clearMessages();
    taskMode = "create";
    taskEditorOpen = true;
    selectedTask = null;
    taskForm = emptyTaskForm();
    focusTaskTitle();
  }

  function startEditTask(task) {
    clearMessages();
    taskMode = "edit";
    taskEditorOpen = true;
    selectedTask = task;
    taskForm = {
      id: task.id,
      title: task.title,
      description: task.description,
      status: task.status || "PENDING",
      due_date: toDateInput(task.due_date)
    };
    focusTaskTitle();
  }

  function closeTaskEditor() {
    clearMessages();
    taskEditorOpen = false;
    taskMode = "create";
    taskForm = emptyTaskForm();
  }

  async function saveTask() {
    clearMessages();
    if (savingTask) {
      return;
    }
    if (!taskForm.title.trim()) {
      errorMessage = "Task title required";
      focusTaskTitle();
      return;
    }

    savingTask = true;
    try {
      const body = taskFormPayload(taskForm);
      const successMessage = taskMode === "edit" && taskForm.id ? "Task updated" : "Task added";
      if (taskMode === "edit" && taskForm.id) {
        await updateTask(authedRequest, taskForm.id, body);
      } else {
        await createTask(authedRequest, body);
      }

      await loadTasks();
      taskMode = "create";
      taskEditorOpen = false;
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
      await removeTask(authedRequest, task.id);
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
      await updateTaskStatus(authedRequest, task, nextStatus);
      await loadTasks();
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
      await Promise.all(targets.map((task) => updateTaskStatus(authedRequest, task, "COMPLETED")));
      await loadTasks();
      showNotice("Visible tasks checked");
    } catch (error) {
      handleError(error);
    }
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

  async function focusTaskTitle() {
    await tick();
    const titleInput = document.getElementById("task-title-input");
    if (!titleInput) {
      return;
    }
    titleInput.scrollIntoView({ block: "nearest", behavior: "smooth" });
    titleInput.focus();
  }
</script>

{#if bootstrapping}
  <main class="loading-page">
    <span class="brand-mark" aria-hidden="true"></span>
    <LoaderCircle class="spin" size={28} aria-hidden="true" />
  </main>
{:else if !authenticated}
  <AuthView
    {authMode}
    {authForm}
    {loadingAuth}
    {errorMessage}
    {noticeMessage}
    onModeChange={(mode) => (authMode = mode)}
    onFormChange={(form) => (authForm = form)}
    onSubmit={handleAuthSubmit}
  />
{:else}
  <div class="app-shell">
    <header class="topbar">
      <div class="brand-row">
        <span class="brand-mark" aria-hidden="true"></span>
        <span>Tasktify</span>
      </div>

      <div class="topbar-actions">
        <nav class="topbar-nav" aria-label="Primary">
          <button
            class="icon-text-button"
            class:active={currentPage === "tasks"}
            type="button"
            on:click={() => navigatePage("tasks")}
          >
            <ListChecks size={17} aria-hidden="true" />
            Tasks
          </button>
          <button
            class="icon-text-button"
            class:active={currentPage === "profile"}
            type="button"
            on:click={() => navigatePage("profile")}
          >
            <User size={17} aria-hidden="true" />
            Profile
          </button>
        </nav>
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

    {#if currentPage === "profile"}
      <main class="workspace profile-workspace">
        <ProfilePage {profile} {accessJwt} />
      </main>
    {:else}
      <main class="workspace">
        <TaskBoard
          {filteredTasks}
          {taskCounts}
          {selectedTask}
          {searchTerm}
          {statusFilter}
          {loadingTasks}
          {visibleIncompleteCount}
          showAddButton={!taskEditorOpen}
          onSearchChange={(value) => (searchTerm = value)}
          onStatusFilterChange={(status) => (statusFilter = status)}
          onCreate={startCreateTask}
          onCheckAll={checkAllVisibleTasks}
          onView={viewTask}
          onEdit={startEditTask}
          onDelete={deleteTask}
          onToggle={toggleTask}
        />

        <aside class="side-column">
          {#if taskEditorOpen}
            <TaskEditor
              {taskMode}
              {taskForm}
              {savingTask}
              onCancel={closeTaskEditor}
              onFormChange={(form) => (taskForm = form)}
              onSubmit={saveTask}
            />
          {:else}
            <TaskDetail {selectedTask} />
          {/if}
        </aside>
      </main>
    {/if}
  </div>
{/if}
