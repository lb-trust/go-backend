"use strict";

const tokenKey = "soc-api-token";
const body = document.querySelector("#wazuh-sources");
const errorMessage = document.querySelector("#wazuh-error");

function formatTime(value) {
  if (!value) return "Jamais";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Inconnue" : date.toLocaleString("fr-FR");
}

function stateLabel(state) {
  switch (state) {
    case "receiving": return "Alertes reçues récemment";
    case "idle": return "Connexion OK, pas d’alerte récente";
    case "error": return "Erreur de connexion";
    case "unknown": return "Premier contrôle en attente";
    default: return state || "Inconnu";
  }
}

function addCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value;
  row.append(cell);
  return cell;
}

async function refreshWazuhStatus() {
  if (!sessionStorage.getItem(tokenKey)) {
    document.querySelector("#wazuh-overall-state").textContent = "Connexion requise";
    document.querySelector("#wazuh-explanation").textContent =
      "Connectez-vous au dashboard avec votre jeton API, puis cliquez sur l’indicateur Wazuh.";
    body.replaceChildren();
    document.querySelector("#empty-wazuh-sources").hidden = true;
    return;
  }

  const refreshButton = document.querySelector("#refresh-wazuh");
  refreshButton.disabled = true;
  errorMessage.textContent = "";
  try {
    const response = await fetch("/api/wazuh/status", {
      headers: { Authorization: `Bearer ${sessionStorage.getItem(tokenKey)}` },
      cache: "no-store",
    });
    const status = await response.json();
    if (response.status === 401) {
      sessionStorage.removeItem(tokenKey);
      throw new Error("Session expirée : reconnectez-vous au dashboard.");
    }
    if (!response.ok) throw new Error(status.error || `Erreur HTTP ${response.status}`);

    body.replaceChildren();
    document.querySelector("#empty-wazuh-sources").hidden = status.sources.length !== 0;
    const hasErrors = status.sources.some((source) => source.state === "error");
    const isReceiving = status.sources.some((source) => source.state === "receiving");
    const overall = document.querySelector("#wazuh-overall-state");
    const explanation = document.querySelector("#wazuh-explanation");
    if (!status.configured) {
      overall.textContent = "Aucune source Wazuh configurée";
      explanation.textContent =
        "Ce statut n’est pas une erreur de connexion : le serveur n’a aucune source Wazuh associée au client de ce jeton. Vérifiez WAZUH_SOURCES_JSON et redémarrez le backend après toute modification.";
    } else if (hasErrors) {
      overall.textContent = "La collecte Wazuh rencontre une erreur";
      explanation.textContent =
        "Consultez le détail de chaque source ci-dessous. Le dernier contrôle et son message d’erreur aident à diagnostiquer la connexion.";
    } else if (isReceiving) {
      overall.textContent = "Des alertes Wazuh arrivent";
      explanation.textContent =
        "Au moins une source a reçu des alertes récemment. L’heure de la dernière alerte est indiquée ci-dessous.";
    } else if (status.sources.some((source) => source.state === "unknown")) {
      overall.textContent = "Premier contrôle Wazuh en attente";
      explanation.textContent =
        "Une source est configurée. Le collecteur n’a pas encore terminé son premier contrôle.";
    } else {
      overall.textContent = "Wazuh joignable, aucune alerte récente";
      explanation.textContent =
        "Le dernier contrôle s’est terminé sans erreur, mais aucune alerte n’a été reçue dans la période récente.";
    }

    for (const source of status.sources) {
      const row = document.createElement("tr");
      const sourceName = `${source.tenant_id} · ${source.alerts_index}`;
      const sourceCell = addCell(row, sourceName);
      sourceCell.title = sourceName;
      const stateCell = addCell(row, stateLabel(source.state));
      stateCell.className = `maintenance-state ${source.state}`;
      addCell(row, formatTime(source.last_check));
      addCell(row, formatTime(source.last_success));
      addCell(row, String(source.alerts_received));
      addCell(row, formatTime(source.last_alert));
      addCell(row, source.error || "—");
      body.append(row);
    }
  } catch (error) {
    document.querySelector("#wazuh-overall-state").textContent = "Impossible de lire l’état Wazuh";
    document.querySelector("#wazuh-explanation").textContent =
      "La page n’a pas pu récupérer le statut auprès du backend.";
    errorMessage.textContent = error.message;
  } finally {
    refreshButton.disabled = false;
  }
}

document.querySelector("#refresh-wazuh").addEventListener("click", refreshWazuhStatus);
setInterval(refreshWazuhStatus, 10000);
refreshWazuhStatus();
