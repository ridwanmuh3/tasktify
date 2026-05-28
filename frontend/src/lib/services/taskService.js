import { normalizeTask, taskPayload } from "../domain/task.js";

export async function listTasks(client) {
  const { payload } = await client("/api/tasks/");
  return (payload?.data || []).map(normalizeTask);
}

export async function getTask(client, task) {
  const { payload } = await client(`/api/tasks/${task.id}`);
  return normalizeTask(payload?.data || task);
}

export async function createTask(client, body) {
  return client("/api/tasks/", {
    method: "POST",
    body
  });
}

export async function updateTask(client, taskId, body) {
  return client(`/api/tasks/${taskId}`, {
    method: "PUT",
    body
  });
}

export async function deleteTask(client, taskId) {
  return client(`/api/tasks/${taskId}`, {
    method: "DELETE"
  });
}

export async function updateTaskStatus(client, task, status) {
  return updateTask(client, task.id, taskPayload({ ...task, status }));
}
