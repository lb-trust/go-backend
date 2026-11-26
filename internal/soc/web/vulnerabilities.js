"use strict";

const sessionKey = "soc-admin-session";
const agentSearch = document.querySelector("#agent-search");
const agentList = document.querySelector("#wazuh-agent-list");
const agentListMessage = document.querySelector("#agent-list-message");
const message = document.querySelector("#vulnerability-message");
const results = document.querySelector("#vulnerability-dialog");
const body = document.querySelector("#vulnerability-body");
const copyButton = document.querySelector("#copy-vulnerabilities");
const upgradeCommandValue = document.querySelector("#upgrade-command-value");
const upgradeCommandNote = document.querySelector("#upgrade-command-note");
const copyUpgradeCommandButton = document.querySelector("#copy-upgrade-command");
let latestInventory = null;
let latestUpgradeCommand = "";
let agents = [];
let inventoryLoading = false;
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

async function loadAgents() {
  const response = await fetch("/api/vulnerabilities/agents", {
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

function renderAgents() {
  const searchTerm = agentSearch.value.trim().toLocaleLowerCase("fr-FR");
  const matchingAgents = agents.filter((agent) =>
    [agent.name, agent.id, agent.ip].some((value) =>
      (value || "").toLocaleLowerCase("fr-FR").includes(searchTerm)),
  );
  agentList.replaceChildren();
  for (const agent of matchingAgents) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "wazuh-agent";
    const name = document.createElement("strong");
    name.textContent = agent.name || `Agent ${agent.id}`;
    const details = document.createElement("span");
    details.textContent = [
      `ID : ${agent.id}`,
      agent.ip ? `IP : ${agent.ip}` : "",
    ].filter(Boolean).join(" · ");
    button.append(name, details);
    button.addEventListener("click", () => selectAgent(agent, button));
    item.append(button);
    agentList.append(item);
  }
  agentListMessage.textContent = matchingAgents.length
    ? ""
    : "Aucun agent ne correspond à cette recherche.";
}

async function selectAgent(agent, selectedButton) {
  if (inventoryLoading) return;
  inventoryLoading = true;
  agentSearch.disabled = true;
  for (const button of agentList.querySelectorAll("button")) button.disabled = true;
  selectedButton.setAttribute("aria-busy", "true");
  message.textContent = `Chargement du récapitulatif de ${agent.name || agent.id}…`;
  document.querySelector("#agent-heading").textContent = `Agent ${agent.id}${agent.name ? ` — ${agent.name}` : ""}`;
  document.querySelector("#agent-details").textContent = "";
  document.querySelector("#vulnerability-count").textContent = "";
  document.querySelector("#vulnerability-warning").hidden = true;
  document.querySelector("#empty-vulnerabilities").hidden = true;
  body.replaceChildren();
  copyButton.disabled = true;
  results.showModal();
  try {
    await renderInventory(await searchVulnerabilities(agent.id));
    message.textContent = "";
  } catch (error) {
    message.textContent = error.message;
  } finally {
    inventoryLoading = false;
    agentSearch.disabled = false;
    for (const button of agentList.querySelectorAll("button")) button.disabled = false;
    selectedButton.removeAttribute("aria-busy");
  }
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

function upgradeCommand(inventory) {
  const os = `${inventory.os_platform || ""} ${inventory.os_name || ""}`.toLocaleLowerCase("fr-FR");
  if (/\bwindows\b/.test(os)) {
    return {
      command: "winget upgrade --all",
      note: "Met à jour les applications gérées par winget. Les mises à jour Windows restent à effectuer via Windows Update.",
    };
  }
  if (/\b(ubuntu|debian|linux mint|pop!_os)\b/.test(os)) {
    return {
      command: "sudo apt update && sudo apt upgrade",
      note: "Met à jour les paquets de la distribution. Des droits administrateur peuvent être demandés.",
    };
  }
  if (/\bfedora\b/.test(os)) {
    return {
      command: "sudo dnf upgrade --refresh",
      note: "Met à jour les paquets Fedora. Des droits administrateur peuvent être demandés.",
    };
  }
  if (/\b(rhel|red hat|rocky|alma linux|almalinux|centos|oracle linux)\b/.test(os)) {
    return {
      command: "sudo dnf upgrade",
      note: "Met à jour les paquets de la distribution. Des droits administrateur peuvent être demandés.",
    };
  }
  if (/\b(alpine)\b/.test(os)) {
    return {
      command: "sudo apk update && sudo apk upgrade",
      note: "Met à jour les paquets Alpine. Des droits administrateur peuvent être demandés.",
    };
  }
  if (/\b(arch|manjaro)\b/.test(os)) {
    return {
      command: "sudo pacman -Syu",
      note: "Met à jour les paquets de la distribution. Des droits administrateur peuvent être demandés.",
    };
  }
  if (/\b(opensuse|suse|sles)\b/.test(os)) {
    return {
      command: "sudo zypper refresh && sudo zypper update",
      note: "Met à jour les paquets de la distribution. Des droits administrateur peuvent être demandés.",
    };
  }
  if (/\b(macos|mac os|darwin)\b/.test(os)) {
    return {
      command: "sudo softwareupdate --install --all",
      note: "Installe les mises à jour macOS disponibles. Un redémarrage peut être nécessaire.",
    };
  }
  return null;
}

function renderInventory(inventory) {
  latestInventory = inventory;
  const upgrade = upgradeCommand(inventory);
  latestUpgradeCommand = upgrade ? upgrade.command : "";
  upgradeCommandValue.textContent = latestUpgradeCommand || "Commande indisponible pour cet OS";
  upgradeCommandNote.textContent = upgrade
    ? upgrade.note
    : "La distribution n’est pas identifiée assez précisément pour proposer une commande sûre.";
  copyUpgradeCommandButton.disabled = !latestUpgradeCommand;
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
  return inventory;
}

agentSearch.addEventListener("input", renderAgents);
document.querySelector("#close-vulnerabilities").addEventListener("click", () => results.close());
results.addEventListener("click", (event) => {
  if (event.target === results) results.close();
});

loadAgents().then((result) => {
  agents = result;
  renderAgents();
}).catch((error) => {
  agentListMessage.textContent = error.message;
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

copyUpgradeCommandButton.addEventListener("click", async () => {
  if (!latestUpgradeCommand) return;
  try {
    await navigator.clipboard.writeText(latestUpgradeCommand);
    message.textContent = "Commande upgrade copiée.";
  } catch {
    message.textContent = "Impossible d’accéder au presse-papiers dans ce navigateur.";
  }
});
