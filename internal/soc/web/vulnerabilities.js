"use strict";

const sessionKey = "soc-admin-session";
const searchForm = document.querySelector("#vulnerability-search");
const searchButton = document.querySelector("#search-agent");
const message = document.querySelector("#vulnerability-message");
const results = document.querySelector("#vulnerability-results");
const body = document.querySelector("#vulnerability-body");
const copyButton = document.querySelector("#copy-vulnerabilities");
let latestInventory = null;
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

async function searchVulnerabilities(searchTerm) {
  const response = await fetch(`/api/vulnerabilities?search=${encodeURIComponent(searchTerm)}`, {
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

function inventoryDetails(inventory) {
  const osLabel = inventory.os_name || inventory.os_platform;
  const osDetails = osLabel
    ? `OS : ${osLabel}${inventory.os_name && inventory.os_platform ? ` (${inventory.os_platform})` : ""}${inventory.os_version ? ` — ${inventory.os_version}` : ""}`
    : "";
  return [
    inventory.agent_ip ? `IP : ${inventory.agent_ip}` : "",
    osDetails,
  ].filter(Boolean);
}

function renderInventory(inventory) {
  latestInventory = inventory;
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
  document.querySelector("#agent-heading").textContent = inventory.agent_id
    ? `Agent ${inventory.agent_id}${agentName}`
    : `Aucun agent trouvé pour « ${inventory.search} »`;
  document.querySelector("#agent-details").textContent = inventoryDetails(inventory).join(" · ");
  document.querySelector("#vulnerability-count").textContent =
    `${inventory.software.length} logiciel(s) · ${inventory.total_detections} détection(s)`;
  copyButton.disabled = inventory.software.length === 0;
  document.querySelector("#empty-vulnerabilities").hidden = inventory.software.length > 0;
  const warning = document.querySelector("#vulnerability-warning");
  warning.hidden = !inventory.truncated;
  warning.textContent = inventory.truncated
    ? "Résultats limités à 10 000 détections ; certains logiciels peuvent ne pas apparaître."
    : "";
  results.hidden = false;
  return inventory;
}

searchForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const searchTerm = document.querySelector("#agent-search").value.trim();
  searchButton.disabled = true;
  message.textContent = "Recherche dans l’inventaire Wazuh…";
  results.hidden = true;
  try {
    await renderInventory(await searchVulnerabilities(searchTerm));
    message.textContent = "";
  } catch (error) {
    message.textContent = error.message;
  } finally {
    searchButton.disabled = false;
  }
});

copyButton.addEventListener("click", async () => {
  if (!latestInventory) return;
  const agent = latestInventory.agent_id
    ? `Agent ${latestInventory.agent_id}${latestInventory.agent_name ? ` — ${latestInventory.agent_name}` : ""}`
    : `Aucun agent trouvé pour « ${latestInventory.search} »`;
  const details = inventoryDetails(latestInventory);
  const rows = latestInventory.software.map((software) =>
    `- ${software.name} ${software.version} — ${priorityLabels[software.priority] || priorityLabels.unknown} — ${software.detections} détection(s)`,
  );
  const text = [agent, ...details, "", ...rows].join("\n");
  try {
    await navigator.clipboard.writeText(text);
    message.textContent = "Liste copiée.";
  } catch {
    message.textContent = "Impossible d’accéder au presse-papiers dans ce navigateur.";
  }
});
