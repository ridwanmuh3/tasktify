export function emptyTaskForm() {
  return {
    id: "",
    title: "",
    description: "",
    status: "PENDING",
    due_date: ""
  };
}

export function normalizeTask(task) {
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

export function taskFormPayload(form) {
  return {
    title: form.title.trim(),
    description: form.description.trim(),
    status: form.status,
    due_date: dateInputToMs(form.due_date)
  };
}

export function taskPayload(task) {
  return {
    title: task.title,
    description: task.description || "",
    status: task.status || "PENDING",
    due_date: task.due_date || 0
  };
}

export function matchesTask(task, query, filter) {
  const statusMatch = filter === "ALL" || task.status === filter;
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return statusMatch;
  }

  const text = `${task.title} ${task.description} ${task.status}`.toLowerCase();
  return statusMatch && text.includes(normalizedQuery);
}

export function buildTaskCounts(sourceTasks) {
  return {
    ALL: sourceTasks.length,
    PENDING: sourceTasks.filter((task) => task.status === "PENDING").length,
    IN_PROGRESS: sourceTasks.filter((task) => task.status === "IN_PROGRESS").length,
    COMPLETED: sourceTasks.filter((task) => task.status === "COMPLETED").length
  };
}

export function statusLabel(status) {
  if (status === "IN_PROGRESS") {
    return "In progress";
  }
  if (status === "COMPLETED") {
    return "Completed";
  }
  return "Pending";
}

export function statusClass(status) {
  return status.toLowerCase().replace("_", "-");
}

export function dateInputToMs(value) {
  if (!value) {
    return 0;
  }
  return new Date(`${value}T00:00:00`).getTime();
}

export function toDateInput(ms) {
  if (!ms) {
    return "";
  }
  const date = new Date(ms);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

export function formatTaskDate(ms) {
  if (!ms) {
    return "No due date";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium"
  }).format(new Date(ms));
}

export function formatTimestamp(ms) {
  if (!ms) {
    return "-";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(ms));
}
