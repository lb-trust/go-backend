"use strict";

const tokenKey = "soc-api-token";
const loginPanel = document.querySelector("#login-panel");
const dashboard = document.querySelector("#dashboard");
const loginForm = document.querySelector("#login-form");
const tokenInput = document.querySelector("#token");
const connectionState = document.querySelector("#connection-state");
const pageMessage = document.querySelector("#page-message");
const statusLabels = {
  open: "Ouvert",
  investigating: "En cours",
  resolved: "Résolu",
  false_positive: "Faux positif",
};
const queueLabels = {
  pending: "En attente",
  processing: "En cours",
  done: "Terminé",
  failed: "Échec",
};
let refreshTimer;

function api(path, options = {}) {
  return fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${sessionStorage.getItem(tokenKey) || ""}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  }).then(async (response) => {
    if (response.status === 401) {
      disconnect();
      throw new Error("Session expirée : reconnectez-vous avec votre jeton API.");
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Erreur HTTP ${response.status}`);
    return data;
  });
}

function setConnected(connected) {
  const wasConnected = !dashboard.hidden;
  loginPanel.hidden = connected;
  dashboard.hidden = !connected;
  connectionState.textContent = connected ? "Connecté" : "Déconnecté";
  connectionState.classList.toggle("online", connected);
  if (wasConnected === connected) return;
  if (refreshTimer) clearInterval(refreshTimer);
  if (connected) refreshTimer = setInterval(refreshDashboard, 10000);
}

function disconnect() {
  sessionStorage.removeItem(tokenKey);
  setConnected(false);
}

function cell(row, value) {
  const element = document.createElement("td");
  element.textContent = value;
  row.append(element);
  return element;
}

function badge(row, label, style) {
  const element = document.createElement("span");
  element.className = `badge ${style}`;
  element.textContent = label;
  const wrapper = document.createElement("td");
  wrapper.append(element);
  row.append(wrapper);
}

function renderIncidents(incidents, enabled) {
  const body = document.querySelector("#incidents-body");
  body.replaceChildren();
  const minLevel = Number(document.querySelector("#level-filter").value || 0);
  const severity = document.querySelector("#severity-filter").value;
  const filtered = incidents.filter((incident) =>
    incident.rule_level >= minLevel && (!severity || incident.severity === severity));
  document.querySelector("#incident-count").textContent = `${filtered.length} affiché(s)`;
  document.querySelector("#empty-incidents").hidden = filtered.length !== 0;

  for (const incident of filtered) {
    const row = document.createElement("tr");
    const title = cell(row, incident.title);
    title.title = `ID : ${incident.id}`;
    badge(row, `${incident.severity} · ${incident.score}`, incident.severity);
    cell(row, statusLabels[incident.status] || incident.status);
    cell(row, `${incident.rule_level}/15`);
    cell(row, String(incident.occurrences));
    const action = document.createElement("td");
    const button = document.createElement("button");
    button.className = "row-action";
    button.type = "button";
    button.textContent = enabled ? "Forcer l’analyse" : "Mettre en file";
    button.title = enabled
      ? "Forcer une nouvelle analyse IA pour cet incident"
      : "Ajouter cet incident à la file ; il sera analysé à la reprise";
    button.addEventListener("click", () => queueAnalysis(button, incident.id));
    action.append(button);
    row.append(action);
    body.append(row);
  }
}

function renderQueue(jobs) {
  const body = document.querySelector("#queue-body");
  body.replaceChildren();
  document.querySelector("#empty-queue").hidden = jobs.length !== 0;
  for (const job of jobs) {
    const row = document.createElement("tr");
    const title = cell(row, job.title);
    title.title = `ID : ${job.incident_id}`;
    badge(row, job.severity, job.severity);
    badge(row, queueLabels[job.status] || job.status, job.status);
    cell(row, String(job.attempts));
    cell(row, job.forced ? "Forcée" : "Automatique");
    body.append(row);
  }
}

async function refreshDashboard() {
  if (!sessionStorage.getItem(tokenKey)) return;
  try {
    pageMessage.textContent = "";
    const status = document.querySelector("#status-filter").value;
    const query = new URLSearchParams({ limit: "100" });
    if (status) query.set("status", status);
    const [incidents, control] = await Promise.all([
      api(`/api/incidents?${query}`),
      api("/api/control/ai"),
    ]);
    document.querySelector("#ai-state").textContent = control.enabled
      ? "Analyse IA activée"
      : "Analyse IA en pause";
    const toggle = document.querySelector("#toggle-ai");
    toggle.textContent = control.enabled ? "Mettre en pause" : "Reprendre l’analyse";
    toggle.disabled = false;
    renderIncidents(incidents, control.enabled);
    renderQueue(control.queue);
    setConnected(true);
  } catch (error) {
    if (sessionStorage.getItem(tokenKey)) pageMessage.textContent = error.message;
    else document.querySelector("#login-error").textContent = error.message;
  }
}

async function queueAnalysis(button, incidentID) {
  button.disabled = true;
  try {
    await api(`/api/incidents/${encodeURIComponent(incidentID)}/queue`, { method: "POST" });
    pageMessage.textContent = "Analyse ajoutée à la file.";
    await refreshDashboard();
  } catch (error) {
    pageMessage.textContent = error.message;
    button.disabled = false;
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = tokenInput.value.trim();
  if (!token) return;
  sessionStorage.setItem(tokenKey, token);
  await refreshDashboard();
  if (sessionStorage.getItem(tokenKey)) tokenInput.value = "";
});

document.querySelector("#toggle-ai").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const state = await api("/api/control/ai");
    await api("/api/control/ai", {
      method: "PATCH",
      body: JSON.stringify({ enabled: !state.enabled }),
    });
    await refreshDashboard();
  } catch (error) {
    pageMessage.textContent = error.message;
    button.disabled = false;
  }
});

document.querySelector("#refresh").addEventListener("click", refreshDashboard);
document.querySelector("#status-filter").addEventListener("change", refreshDashboard);
document.querySelector("#severity-filter").addEventListener("change", refreshDashboard);
document.querySelector("#level-filter").addEventListener("input", refreshDashboard);
document.querySelector("#logout").addEventListener("click", disconnect);

if (sessionStorage.getItem(tokenKey)) {
  refreshDashboard();
}
