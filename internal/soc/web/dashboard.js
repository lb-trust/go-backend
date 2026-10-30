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
const incidentColumns = [
  { key: "incident", label: "Incident", default: true },
  { key: "severity", label: "Sévérité", default: true },
  { key: "status", label: "Statut", default: true },
  { key: "level", label: "Niveau Wazuh", default: true },
  { key: "occurrences", label: "Occurrences", default: true },
  { key: "agentGroups", label: "Groupe(s) de l’agent" },
  { key: "agentName", label: "Nom de l’agent" },
  { key: "agentIP", label: "IP de l’agent" },
  { key: "sourceIP", label: "IP source" },
  { key: "agentID", label: "ID de l’agent" },
  { key: "ai", label: "IA", default: true },
];
const columnsKey = "soc-dashboard-incident-columns";
const columnPicker = document.querySelector("#incident-columns");
const columnSummary = document.querySelector("#columns-summary");
const clientFilter = document.querySelector("#client-filter");
const clientOptions = document.querySelector("#client-options");
let visibleIncidentColumns = loadIncidentColumns();
let latestIncidents = [];
let latestAIEnabled = false;
let latestQueuedIncidentIDs = new Set();
let configuredGroups = null;
let activeIncidentID = "";
let refreshTimer;

function updateColumnFilterSummary() {
  const checkboxes = columnPicker.querySelectorAll("input");
  const selected = columnPicker.querySelectorAll("input:checked");
  columnSummary.textContent = selected.length === checkboxes.length ? "Toutes" : "Personnalisé";
}

function loadIncidentColumns() {
  const defaults = incidentColumns.filter((column) => column.default).map((column) => column.key);
  const stored = localStorage.getItem(columnsKey);
  if (!stored) return defaults;
  try {
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed)) return defaults;
    return parsed.filter((key) => incidentColumns.some((column) => column.key === key));
  } catch {
    return defaults;
  }
}

for (const checkbox of columnPicker.querySelectorAll("input")) {
  checkbox.checked = visibleIncidentColumns.includes(checkbox.value);
  checkbox.addEventListener("change", () => {
    visibleIncidentColumns = Array.from(columnPicker.querySelectorAll("input:checked"))
      .map((input) => input.value);
    localStorage.setItem(columnsKey, JSON.stringify(visibleIncidentColumns));
    updateColumnFilterSummary();
    renderIncidents(latestIncidents, latestAIEnabled);
  });
}
updateColumnFilterSummary();

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
    if (response.status === 204) return null;
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

function formatStatusTime(value) {
  if (!value) return "jamais";
  return new Date(value).toLocaleString("fr-FR");
}

function renderWazuhStatus(status) {
  const indicator = document.querySelector("#wazuh-state");
  indicator.className = "wazuh-status";
  if (!status.configured) {
    indicator.textContent = "Wazuh : non configuré";
    indicator.classList.add("unavailable");
    indicator.title = "Cliquer pour consulter le diagnostic Wazuh.";
    return;
  }
  const lines = status.sources.map((source) => {
    const label = `${source.tenant_id} · ${source.alerts_index}`;
    if (source.state === "unknown") {
      return `${label} : en attente du premier contrôle`;
    }
    if (source.state === "error") {
      return `${label} : erreur de connexion — ${source.error}`;
    }
    if (source.state === "receiving") {
      return `${label} : alertes reçues (${source.alerts_received} au dernier contrôle), dernière alerte ${formatStatusTime(source.last_alert)}`;
    }
    return `${label} : connexion OK, aucune alerte récente (dernier contrôle ${formatStatusTime(source.last_check)}, dernière alerte ${formatStatusTime(source.last_alert)})`;
  });
  const hasError = status.sources.some((source) => source.state === "error");
  const receiving = status.sources.some((source) => source.state === "receiving");
  indicator.textContent = hasError
    ? "Wazuh : erreur"
    : receiving
      ? "Wazuh : alertes reçues"
      : "Wazuh : connecté";
  indicator.classList.add(hasError ? "error" : receiving ? "online" : "idle");
  indicator.title = `Cliquer pour consulter le diagnostic Wazuh.\n${lines.join("\n")}`;
}

function disconnect() {
  sessionStorage.removeItem(tokenKey);
  configuredGroups = null;
  clientOptions.replaceChildren();
  const incidentDialog = document.querySelector("#incident-dialog");
  if (incidentDialog.open) incidentDialog.close();
  activeIncidentID = "";
  setConnected(false);
}

function selectedClients() {
  return Array.from(clientOptions.querySelectorAll("input[data-client]:checked"))
    .map((input) => input.value);
}

function updateClientFilterSummary() {
  const allOption = clientOptions.querySelector("#all-clients");
  const clients = clientOptions.querySelectorAll("input[data-client]");
  const selected = selectedClients();
  allOption.checked = selected.length === clients.length;
  allOption.indeterminate = selected.length > 0 && selected.length < clients.length;
  const summary = clientFilter.querySelector("summary");
  summary.textContent = selected.length === clients.length
    ? "Tous les groupes"
    : selected.length === 1
      ? selected[0]
      : `${selected.length} groupe(s) sélectionné(s)`;
}

function selectedFilterValue(filterID) {
  return document.querySelector(`#${filterID} input:checked`).value;
}

for (const filterID of ["status-filter", "severity-filter"]) {
  const filter = document.querySelector(`#${filterID}`);
  filter.querySelectorAll("input").forEach((input) => {
    input.addEventListener("change", () => {
      filter.querySelector("summary").textContent = input.parentElement.textContent.trim();
      filter.open = false;
      refreshDashboard();
    });
  });
}

function initializeClientFilter(groups) {
  configuredGroups = groups;
  const allLabel = document.createElement("label");
  const allCheckbox = document.createElement("input");
  allCheckbox.type = "checkbox";
  allCheckbox.id = "all-clients";
  allCheckbox.checked = true;
  allLabel.append(allCheckbox, " Tous les groupes");
  clientOptions.replaceChildren(allLabel);
  for (const group of groups) {
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = group;
    checkbox.dataset.client = "true";
    checkbox.checked = true;
    label.append(checkbox, ` ${group}`);
    clientOptions.append(label);
  }
  allCheckbox.addEventListener("change", () => {
    for (const checkbox of clientOptions.querySelectorAll("input[data-client]")) {
      checkbox.checked = allCheckbox.checked;
    }
    updateClientFilterSummary();
    refreshDashboard();
  });
  for (const checkbox of clientOptions.querySelectorAll("input[data-client]")) {
    checkbox.addEventListener("change", () => {
      updateClientFilterSummary();
      refreshDashboard();
    });
  }
  updateClientFilterSummary();
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
  const head = document.querySelector("#incidents-head");
  const body = document.querySelector("#incidents-body");
  const headerRow = document.createElement("tr");
  const columns = incidentColumns.filter((column) => visibleIncidentColumns.includes(column.key));
  for (const column of columns) {
    const heading = document.createElement("th");
    heading.textContent = column.label;
    headerRow.append(heading);
  }
  head.replaceChildren(headerRow);
  body.replaceChildren();
  const minLevel = Number(document.querySelector("#level-filter").value || 0);
  const severity = selectedFilterValue("severity-filter");
  const selected = selectedClients();
  const filtered = incidents.filter((incident) =>
    incident.rule_level >= minLevel &&
    (!severity || incident.severity === severity) &&
    (selected.length === configuredGroups.length ||
      (incident.agent_groups || []).some((group) => selected.includes(group))));
  document.querySelector("#incident-count").textContent = `${filtered.length} affiché(s)`;
  document.querySelector("#empty-incidents").hidden = filtered.length !== 0;

  for (const incident of filtered) {
    const row = document.createElement("tr");
    const queued = latestQueuedIncidentIDs.has(incident.id);
    row.className = queued ? "incident-row queued" : "incident-row";
    row.tabIndex = 0;
    row.setAttribute(
      "aria-label",
      `Ouvrir le détail de l’incident : ${incident.title}${queued ? " (analyse IA en attente ou en cours)" : ""}`,
    );
    if (queued) row.title = "Analyse IA en attente ou en cours";
    row.addEventListener("click", (event) => {
      if (!event.target.closest("button")) openIncidentDetails(incident.id);
    });
    row.addEventListener("keydown", (event) => {
      if ((event.key === "Enter" || event.key === " ") && !event.target.closest("button")) {
        event.preventDefault();
        openIncidentDetails(incident.id);
      }
    });
    for (const column of columns) {
      switch (column.key) {
        case "incident": {
          const title = cell(row, incident.title);
          title.title = `ID : ${incident.id}`;
          break;
        }
        case "severity":
          badge(row, `${incident.severity} · ${incident.score}`, incident.severity);
          break;
        case "status":
          cell(row, statusLabels[incident.status] || incident.status);
          break;
        case "level":
          cell(row, `${incident.rule_level}/15`);
          break;
        case "occurrences":
          cell(row, String(incident.occurrences));
          break;
        case "agentGroups":
          cell(row, (incident.agent_groups || []).join(", ") || "—");
          break;
        case "agentName":
          cell(row, incident.agent_name || "—");
          break;
        case "agentIP":
          cell(row, incident.agent_ip || "—");
          break;
        case "sourceIP":
          cell(row, incident.source_ip || "—");
          break;
        case "agentID": {
          const agentID = cell(row, incident.agent_id || "—");
          if (incident.agent_id) agentID.title = incident.agent_id;
          break;
        }
        case "ai": {
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
          break;
        }
      }
    }
    body.append(row);
  }
}

function setIncidentDetail(incident) {
  document.querySelector("#incident-dialog-title").textContent = incident.title;
  document.querySelector("#detail-severity").textContent =
    `${incident.severity} · ${incident.score}/100`;
  document.querySelector("#detail-current-status").textContent =
    statusLabels[incident.status] || incident.status;
  document.querySelector("#detail-agent").textContent =
    incident.agent_name || incident.agent_id || "—";
  document.querySelector("#detail-groups").textContent =
    (incident.agent_groups || []).join(", ") || "—";
  document.querySelector("#detail-agent-ip").textContent = incident.agent_ip || "—";
  document.querySelector("#detail-source-ip").textContent = incident.source_ip || "—";
  document.querySelector("#detail-level").textContent = `${incident.rule_level}/15`;
  document.querySelector("#detail-occurrences").textContent = String(incident.occurrences);
  document.querySelector("#detail-created").textContent = formatStatusTime(incident.created_at);
  document.querySelector("#detail-updated").textContent = formatStatusTime(incident.updated_at);
  document.querySelector("#detail-analysis").textContent = incident.analysis ||
    "Aucune analyse IA disponible pour cet incident.";
  document.querySelector("#incident-status").value = incident.status;

  const alertContainer = document.querySelector("#detail-alerts");
  alertContainer.replaceChildren();
  for (const alert of incident.alerts || []) {
    const item = document.createElement("article");
    item.className = "incident-alert";
    const heading = document.createElement("div");
    heading.className = "incident-alert-heading";
    const rule = document.createElement("strong");
    rule.textContent = `Règle ${alert.rule_id} · niveau ${alert.rule_level}/15`;
    heading.append(rule);
    const time = document.createElement("span");
    time.className = "muted";
    time.textContent = formatStatusTime(alert.timestamp);
    heading.append(time);
    const description = document.createElement("p");
    description.textContent = alert.description || "Aucune description";
    item.append(heading, description);
    alertContainer.append(item);
  }
  if (!incident.alerts || incident.alerts.length === 0) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "Aucune alerte associée.";
    alertContainer.append(empty);
  }

  const feedbackList = document.querySelector("#detail-feedback");
  feedbackList.replaceChildren();
  for (const feedback of incident.feedback || []) {
    const item = document.createElement("li");
    item.textContent = feedback;
    feedbackList.append(item);
  }
  document.querySelector("#empty-feedback").hidden = (incident.feedback || []).length > 0;
}

async function openIncidentDetails(incidentID) {
  activeIncidentID = incidentID;
  const dialog = document.querySelector("#incident-dialog");
  document.querySelector("#incident-dialog-error").textContent = "";
  document.querySelector("#incident-dialog-title").textContent = "Chargement…";
  dialog.showModal();
  try {
    const incident = await api(`/api/incidents/${encodeURIComponent(incidentID)}`);
    if (activeIncidentID === incidentID) setIncidentDetail(incident);
  } catch (error) {
    document.querySelector("#incident-dialog-error").textContent = error.message;
  }
}

function renderQueue(jobs) {
  const selected = selectedClients();
  const filteredJobs = jobs.filter((job) =>
    selected.length === configuredGroups.length ||
    (job.agent_groups || []).some((group) => selected.includes(group)));
  const body = document.querySelector("#queue-body");
  body.replaceChildren();
  document.querySelector("#empty-queue").hidden = filteredJobs.length !== 0;
  for (const job of filteredJobs) {
    const row = document.createElement("tr");
    cell(row, (job.agent_groups || []).join(", ") || "—");
    const title = cell(row, job.title);
    title.title = `ID : ${job.incident_id}`;
    badge(row, job.severity, job.severity);
    badge(row, queueLabels[job.status] || job.status, job.status);
    cell(row, String(job.attempts));
    cell(row, job.forced ? "Forcée" : "Automatique");
    const action = document.createElement("td");
    if (job.status === "pending" || job.status === "failed") {
      const button = document.createElement("button");
      button.className = "row-action secondary";
      button.type = "button";
      button.textContent = "Retirer";
      button.title = "Retirer ce traitement de la file";
      button.addEventListener("click", () => removeQueuedAnalysis(button, job.incident_id));
      action.append(button);
    } else {
      action.textContent = "—";
    }
    row.append(action);
    body.append(row);
  }
}

async function refreshDashboard() {
  if (!sessionStorage.getItem(tokenKey)) return;
  try {
    pageMessage.textContent = "";
    if (configuredGroups === null) {
      initializeClientFilter(await api("/api/clients"));
    }
    const status = selectedFilterValue("status-filter");
    const query = new URLSearchParams({ limit: "500" });
    if (status) query.set("status", status);
    const [incidents, control, wazuhStatus] = await Promise.all([
      api(`/api/incidents?${query}`),
      api("/api/control/ai"),
      api("/api/wazuh/status"),
    ]);
    renderWazuhStatus(wazuhStatus);
    const queue = control.queue;
    latestQueuedIncidentIDs = new Set(
      queue
        .filter((job) => job.status === "pending" || job.status === "processing")
        .map((job) => job.incident_id),
    );
    queue.sort((a, b) => {
      const priority = { processing: 0, pending: 1, failed: 2, done: 3 };
      return priority[a.status] - priority[b.status] ||
        new Date(b.created_at) - new Date(a.created_at);
    });
    document.querySelector("#ai-state").textContent = control.enabled
      ? "Analyse IA activée"
      : "Analyse IA en pause";
    const toggle = document.querySelector("#toggle-ai");
    toggle.textContent = control.enabled ? "Mettre en pause" : "Reprendre l’analyse";
    toggle.disabled = false;
    latestIncidents = incidents;
    latestAIEnabled = control.enabled;
    renderIncidents(incidents, control.enabled);
    renderQueue(queue);
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

async function removeQueuedAnalysis(button, incidentID) {
  button.disabled = true;
  try {
    await api(`/api/incidents/${encodeURIComponent(incidentID)}/queue`, {
      method: "DELETE",
    });
    pageMessage.textContent = "Traitement retiré de la file.";
    await refreshDashboard();
  } catch (error) {
    pageMessage.textContent = error.message;
    button.disabled = false;
  }
}

document.addEventListener("click", (event) => {
  for (const tip of document.querySelectorAll(".help-tip[open]")) {
    if (!tip.contains(event.target)) tip.open = false;
  }
  for (const menu of document.querySelectorAll(".filter-menu[open]")) {
    if (!menu.contains(event.target)) menu.open = false;
  }
});

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
document.querySelector("#level-filter").addEventListener("input", refreshDashboard);
document.querySelector("#logout").addEventListener("click", disconnect);
const incidentDialog = document.querySelector("#incident-dialog");
document.querySelector("#close-incident").addEventListener("click", () => {
  incidentDialog.close();
});
incidentDialog.addEventListener("click", (event) => {
  if (event.target === incidentDialog) incidentDialog.close();
});
incidentDialog.addEventListener("close", () => {
  if (!incidentDialog.open) activeIncidentID = "";
});
document.querySelector("#incident-edit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!activeIncidentID) return;
  const saveButton = document.querySelector("#save-incident");
  saveButton.disabled = true;
  document.querySelector("#incident-dialog-error").textContent = "";
  try {
    const incident = await api(`/api/incidents/${encodeURIComponent(activeIncidentID)}`, {
      method: "PATCH",
      body: JSON.stringify({
        status: document.querySelector("#incident-status").value,
        feedback: document.querySelector("#incident-feedback").value.trim(),
      }),
    });
    document.querySelector("#incident-feedback").value = "";
    setIncidentDetail(incident);
    incidentDialog.close();
    await refreshDashboard();
  } catch (error) {
    document.querySelector("#incident-dialog-error").textContent = error.message;
  } finally {
    saveButton.disabled = false;
  }
});

if (sessionStorage.getItem(tokenKey)) {
  refreshDashboard();
}
