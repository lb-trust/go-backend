"use strict";

const sessionKey = "soc-admin-session";
const searchForm = document.querySelector("#vulnerability-search");
const searchButton = document.querySelector("#search-agent");
const message = document.querySelector("#vulnerability-message");
const results = document.querySelector("#vulnerability-results");
const body = document.querySelector("#vulnerability-body");
const priorityLabels = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  unknown: "À qualifier",
};

if (!sessionStorage.getItem(sessionKey)) {
  window.location.replace("/");
}

async function searchVulnerabilities(agentID) {
  const response = await fetch(`/api/vulnerabilities?agent_id=${encodeURIComponent(agentID)}`, {
    headers: { Authorization: `Bearer ${sessionStorage.getItem(sessionKey) || ""}` },
  });
  if (response.status === 401) {
    sessionStorage.removeItem(sessionKey);
    window.location.replace("/");
    throw new Error("Session expirée ; reconnectez-vous.");
  }
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Erreur HTTP ${response.status}`);
  return result;
}

function renderInventory(inventory) {
  body.replaceChildren();
  for (const software of inventory.software) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = software.name;
    const version = document.createElement("td");
    version.textContent = software.version;
    const priority = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${software.priority}`;
    badge.textContent = priorityLabels[software.priority] || priorityLabels.unknown;
    priority.append(badge);
    const detections = document.createElement("td");
    detections.textContent = String(software.detections);
    row.append(name, version, priority, detections);
    body.append(row);
  }

  const agentName = inventory.agent_name ? ` — ${inventory.agent_name}` : "";
  document.querySelector("#agent-heading").textContent = `Agent ${inventory.agent_id}${agentName}`;
  document.querySelector("#vulnerability-count").textContent =
    `${inventory.software.length} logiciel(s) · ${inventory.total_detections} détection(s)`;
  document.querySelector("#empty-vulnerabilities").hidden = inventory.software.length > 0;
  const warning = document.querySelector("#vulnerability-warning");
  warning.hidden = !inventory.truncated;
  warning.textContent = inventory.truncated
    ? "Résultats limités à 10 000 détections ; certains logiciels peuvent ne pas apparaître."
    : "";
  results.hidden = false;
}

searchForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const agentID = document.querySelector("#agent-id").value.trim();
  searchButton.disabled = true;
  message.textContent = "Recherche dans l’inventaire Wazuh…";
  results.hidden = true;
  try {
    renderInventory(await searchVulnerabilities(agentID));
    message.textContent = "";
  } catch (error) {
    message.textContent = error.message;
  } finally {
    searchButton.disabled = false;
  }
});
