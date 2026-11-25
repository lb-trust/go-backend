"use strict";

const tokenKey = "soc-admin-session";
const setupPanel = document.querySelector("#setup-panel");
const loginPanel = document.querySelector("#login-panel");
const dashboard = document.querySelector("#dashboard");
const setupForm = document.querySelector("#setup-form");
const loginForm = document.querySelector("#login-form");
const topbar = document.querySelector("#topbar");
const headerActions = document.querySelector("#header-actions");
const accountMenu = document.querySelector("#account-menu");
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
  { key: "occurrences", label: "Occurrences (événement principal)", default: true },
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
let activePrimaryAlert = null;
let activePrimaryOccurrenceTimes = [];
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
      throw new Error("Session expirée : reconnectez-vous avec votre compte.");
    }
    if (response.status === 204) return null;
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Erreur HTTP ${response.status}`);
    return data;
  });
}

function setConnected(connected) {
  const wasConnected = !dashboard.hidden;
  setupPanel.hidden = true;
  loginPanel.hidden = connected;
  dashboard.hidden = !connected;
  topbar.hidden = false;
  headerActions.hidden = !connected;
  accountMenu.hidden = !connected;
  document.body.classList.toggle("auth-screen", !connected);
  if (!connected) accountMenu.open = false;
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
    const label = source.alerts_index;
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
  configuredGroups = [...groups].sort((a, b) => a.localeCompare(b, "fr", { sensitivity: "base" }));
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
  const alerts = incident.alerts || [];
  activePrimaryAlert = alerts.find((alert) => alert.id === incident.primary_alert_id) || null;
  activePrimaryOccurrenceTimes = incident.primary_occurrence_times || [];
  document.querySelector("#detail-primary-description").textContent = activePrimaryAlert
    ? `Règle ${activePrimaryAlert.rule_id} · niveau ${activePrimaryAlert.rule_level}/15 · ${activePrimaryAlert.occurrences} ${activePrimaryAlert.occurrences > 1 ? "occurrences" : "occurrence"} — ${activePrimaryAlert.description || "Aucune description"}`
    : "";
  document.querySelector("#view-primary-alert").hidden = !activePrimaryAlert;
  document.querySelector("#detail-primary-unavailable").hidden = Boolean(activePrimaryAlert);
  const primaryOccurrences = document.querySelector("#detail-primary-occurrences");
  primaryOccurrences.replaceChildren();
  const primaryOccurrencesLabel = document.querySelector("#detail-primary-occurrences-label");
  primaryOccurrencesLabel.hidden = !activePrimaryAlert;
  for (const timestamp of incident.primary_occurrence_times || []) {
    const item = document.createElement("li");
    item.textContent = formatStatusTime(timestamp);
    primaryOccurrences.append(item);
  }
  primaryOccurrences.hidden = !activePrimaryAlert;
  document.querySelector("#detail-alert-count").textContent =
    `(${alerts.filter((alert) => alert.id !== incident.primary_alert_id).length} groupes)`;
  alertContainer.replaceChildren();
  for (const alert of alerts.filter((item) => item.id !== incident.primary_alert_id)) {
    const item = document.createElement("article");
    item.className = "incident-alert";
    item.tabIndex = 0;
    item.setAttribute("role", "button");
    item.setAttribute("aria-label", `Alerte, règle ${alert.rule_id}, ${alert.occurrences} ${alert.occurrences > 1 ? "occurrences" : "occurrence"}. Double-cliquez ou appuyez sur Entrée pour ouvrir le détail.`);
    item.addEventListener("dblclick", () => openAlertDetails(alert));
    item.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openAlertDetails(alert);
      }
    });
    const heading = document.createElement("div");
    heading.className = "incident-alert-heading";
    const rule = document.createElement("strong");
    rule.textContent = `Règle ${alert.rule_id} · niveau ${alert.rule_level}/15`;
    heading.append(rule);
    const occurrences = document.createElement("span");
    occurrences.className = "badge";
    occurrences.textContent = `${alert.occurrences} ${alert.occurrences > 1 ? "occurrences" : "occurrence"}`;
    heading.append(occurrences);
    const time = document.createElement("span");
    time.className = "muted";
    time.textContent = formatStatusTime(alert.timestamp);
    heading.append(time);
    const description = document.createElement("p");
    description.textContent = alert.description || "Aucune description";
    item.append(heading, description);
    alertContainer.append(item);
  }
  if (!alerts.some((alert) => alert.id !== incident.primary_alert_id)) {
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

function buildPrimaryAlertReport(alert, occurrenceTimes) {
  const timeline = occurrenceTimes.map((occurredAt, index) => {
    const currentTime = new Date(occurredAt).getTime();
    const previousTime = index > 0 ? new Date(occurrenceTimes[index - 1]).getTime() : null;
    return {
      occurred_at: occurredAt,
      seconds_since_previous: previousTime === null || !Number.isFinite(currentTime) ||
        !Number.isFinite(previousTime)
        ? null
        : (currentTime - previousTime) / 1000,
    };
  });
  const firstSeen = timeline[0]?.occurred_at || alert.first_seen || null;
  const lastSeen = timeline[timeline.length - 1]?.occurred_at || alert.last_seen || null;
  const firstTime = firstSeen ? new Date(firstSeen).getTime() : NaN;
  const lastTime = lastSeen ? new Date(lastSeen).getTime() : NaN;
  const durationSeconds = Number.isFinite(firstTime) && Number.isFinite(lastTime)
    ? (lastTime - firstTime) / 1000
    : null;

  return {
    event: {
      id: alert.id,
      wazuh_id: alert.wazuh_id || null,
      timestamp: alert.timestamp,
      rule: {
        id: alert.rule_id,
        level: alert.rule_level,
        description: alert.description,
      },
      agent: {
        id: alert.agent_id || null,
        name: alert.agent_name || null,
        ip: alert.agent_ip || null,
        groups: alert.agent_groups || [],
      },
      source_ip: alert.source_ip || null,
      destination_ip: alert.dest_ip || null,
      location: alert.location || null,
    },
    occurrences: {
      total: alert.occurrences,
      last_6_hours: alert.occurrences_6h,
      first_seen: firstSeen,
      last_seen: lastSeen,
      observed_duration_seconds: durationSeconds,
      average_interval_seconds: durationSeconds !== null && timeline.length > 1
        ? durationSeconds / (timeline.length - 1)
        : null,
      timeline,
    },
    wazuh_event: alert.raw || {},
  };
}

function openAlertDetails(alert, occurrenceTimes) {
  document.querySelector("#alert-dialog-title").textContent =
    `Règle ${alert.rule_id} · ${alert.description || "Aucune description"}`;
  document.querySelector("#alert-detail-occurrences").textContent =
    `${alert.occurrences} ${alert.occurrences > 1 ? "occurrences" : "occurrence"}`;
  document.querySelector("#alert-detail-first-seen").textContent = formatStatusTime(alert.first_seen);
  document.querySelector("#alert-detail-last-seen").textContent = formatStatusTime(alert.last_seen);
  document.querySelector("#alert-detail-agent").textContent =
    alert.agent_name || alert.agent_id || "—";
  document.querySelector("#alert-detail-source").textContent = alert.source_ip || "—";
  document.querySelector("#alert-detail-destination").textContent = alert.dest_ip || "—";
  document.querySelector("#alert-detail-location").textContent = alert.location || "—";
  const isPrimaryAlert = occurrenceTimes !== undefined;
  document.querySelector("#alert-detail-json-title").textContent = isPrimaryAlert
    ? "JSON enrichi de l’événement principal"
    : "Événement Wazuh brut";
  document.querySelector("#alert-detail-raw").textContent =
    JSON.stringify(
      isPrimaryAlert ? buildPrimaryAlertReport(alert, occurrenceTimes) : alert.raw || {},
      null,
      2,
    );
  document.querySelector("#alert-dialog").showModal();
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
  if (!accountMenu.contains(event.target)) accountMenu.open = false;
});

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorMessage = document.querySelector("#setup-error");
  const button = setupForm.querySelector("button[type=submit]");
  errorMessage.textContent = "";
  button.disabled = true;
  const username = document.querySelector("#setup-username").value.trim();
  try {
    const response = await fetch("/api/setup/admin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        password: document.querySelector("#setup-password").value,
        confirm_password: document.querySelector("#setup-confirm-password").value,
      }),
    });
    const result = response.status === 201 ? {} : await response.json();
    if (!response.ok) throw new Error(result.error || `Erreur HTTP ${response.status}`);
    setupPanel.hidden = true;
    loginPanel.hidden = false;
    document.querySelector("#username").value = username;
    document.querySelector("#login-error").textContent = "";
    setupForm.reset();
    document.querySelector("#password").focus();
  } catch (error) {
    errorMessage.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorMessage = document.querySelector("#login-error");
  errorMessage.textContent = "";
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#username").value.trim(),
        password: document.querySelector("#password").value,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Erreur HTTP ${response.status}`);
    sessionStorage.setItem(tokenKey, result.token);
    document.querySelector("#password").value = "";
    await refreshDashboard();
  } catch (error) {
    errorMessage.textContent = error.message;
  }
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
document.querySelector("#logout").addEventListener("click", async () => {
  const token = sessionStorage.getItem(tokenKey);
  try {
    if (token) {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
    }
  } catch (error) {
    console.error("Impossible de révoquer la session côté serveur :", error);
  } finally {
    disconnect();
  }
});
const incidentDialog = document.querySelector("#incident-dialog");
const alertDialog = document.querySelector("#alert-dialog");
document.querySelector("#close-incident").addEventListener("click", () => {
  incidentDialog.close();
});
document.querySelector("#close-alert").addEventListener("click", () => {
  alertDialog.close();
});
document.querySelector("#view-primary-alert").addEventListener("click", () => {
  if (activePrimaryAlert) openAlertDetails(activePrimaryAlert, activePrimaryOccurrenceTimes);
});
alertDialog.addEventListener("click", (event) => {
  if (event.target === alertDialog) alertDialog.close();
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

document.querySelector("#delete-incident").addEventListener("click", async (event) => {
  const incidentID = activeIncidentID;
  if (!incidentID) return;
  const title = document.querySelector("#incident-dialog-title").textContent;
  if (!window.confirm(
    `Supprimer définitivement l’incident « ${title} » ? Ses commentaires, son analyse et son traitement IA seront supprimés. Les alertes Wazuh sources seront conservées.`,
  )) return;

  const button = event.currentTarget;
  button.disabled = true;
  document.querySelector("#incident-dialog-error").textContent = "";
  try {
    await api(`/api/incidents/${encodeURIComponent(incidentID)}`, { method: "DELETE" });
    incidentDialog.close();
    activeIncidentID = "";
    await refreshDashboard();
    if (!pageMessage.textContent) {
      pageMessage.textContent = "Incident supprimé. Les alertes Wazuh sources sont conservées.";
    }
  } catch (error) {
    document.querySelector("#incident-dialog-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

async function initializeDashboard() {
  if (sessionStorage.getItem("soc-password-changed")) {
    sessionStorage.removeItem("soc-password-changed");
  }
  try {
    const response = await fetch("/api/setup/status", { cache: "no-store" });
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || `Erreur HTTP ${response.status}`);
    if (status.required) {
      sessionStorage.removeItem(tokenKey);
      setupPanel.hidden = false;
      loginPanel.hidden = true;
      return;
    }
    setupPanel.hidden = true;
    loginPanel.hidden = false;
    if (sessionStorage.getItem(tokenKey)) refreshDashboard();
  } catch (error) {
    loginPanel.hidden = false;
    loginError.textContent = error.message;
  }
}

initializeDashboard();
