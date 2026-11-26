"use strict";

const sessionKey = "soc-admin-session";
const setupPanel = document.querySelector("#setup-panel");
const loginPanel = document.querySelector("#login-panel");
const homeDashboard = document.querySelector("#home-dashboard");
const headerActions = document.querySelector("#header-actions");
const setupForm = document.querySelector("#setup-form");
const loginForm = document.querySelector("#login-form");
const menu = document.querySelector("#account-menu");

function showLogin(error = "") {
  homeDashboard.hidden = true;
  headerActions.hidden = true;
  setupPanel.hidden = true;
  loginPanel.hidden = false;
  document.body.classList.add("auth-screen");
  document.querySelector("#login-error").textContent = error;
}

async function api(path) {
  const response = await fetch(path, {
    headers: { Authorization: `Bearer ${sessionStorage.getItem(sessionKey) || ""}` },
    cache: "no-store",
  });
  if (response.status === 401) {
    sessionStorage.removeItem(sessionKey);
    showLogin("Session expirée : reconnectez-vous avec votre compte.");
    throw new Error("Session expirée.");
  }
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Erreur HTTP ${response.status}`);
  return data;
}

function setValue(selector, value) {
  document.querySelector(selector).textContent = value;
}

function renderCollection(status) {
  if (!status.configured || !status.sources.length) {
    setValue("#home-collection-state", "Non configurée");
    setValue("#home-collection-details", "Aucune source Wazuh associée à ce compte.");
    return;
  }
  const sources = status.sources;
  const errored = sources.filter((source) => source.state === "error");
  const pending = sources.filter((source) => source.state === "unknown");
  if (errored.length) {
    setValue("#home-collection-state", "En erreur");
    setValue("#home-collection-details", `${errored.length} source(s) en erreur sur ${sources.length}.`);
  } else if (pending.length) {
    setValue("#home-collection-state", "En attente");
    setValue("#home-collection-details", `${pending.length} source(s) en attente du premier contrôle.`);
  } else {
    setValue("#home-collection-state", "Opérationnelle");
    setValue("#home-collection-details", `${sources.length} source(s) Wazuh joignable(s).`);
  }
}

async function refreshHome() {
  const refreshButton = document.querySelector("#refresh-home");
  refreshButton.disabled = true;
  setupPanel.hidden = true;
  loginPanel.hidden = true;
  setValue("#home-error", "");
  const results = await Promise.allSettled([
    api("/api/dashboard"),
    api("/api/vulnerabilities/agents"),
    api("/api/wazuh/status"),
  ]);
  if (!sessionStorage.getItem(sessionKey)) {
    refreshButton.disabled = false;
    return;
  }

  homeDashboard.hidden = false;
  headerActions.hidden = false;
  document.body.classList.remove("auth-screen");
  const [dashboard, agents, collection] = results;
  if (dashboard.status === "fulfilled") {
    setValue("#home-alert-count", dashboard.value.alerts.toLocaleString("fr-FR"));
    setValue("#home-open-count", dashboard.value.open_incidents.toLocaleString("fr-FR"));
    setValue(
      "#home-events-summary",
      `${dashboard.value.incidents.toLocaleString("fr-FR")} incident(s) au total, dont ${dashboard.value.open_incidents.toLocaleString("fr-FR")} ouvert(s).`,
    );
  } else {
    setValue("#home-alert-count", "Indisponible");
    setValue("#home-open-count", "Indisponible");
    setValue("#home-events-summary", "Impossible de récupérer le résumé des événements.");
    setValue("#home-error", dashboard.reason.message);
  }

  if (agents.status === "fulfilled") {
    const count = agents.value.length;
    setValue("#home-agent-count", count.toLocaleString("fr-FR"));
    setValue(
      "#home-updates-summary",
      `${count.toLocaleString("fr-FR")} agent(s) connu(s). Sélectionnez-en un pour consulter les versions détectées et les commandes adaptées.`,
    );
  } else {
    setValue("#home-agent-count", "Indisponible");
    setValue("#home-updates-summary", `Impossible de lire les agents du manager Wazuh : ${agents.reason.message}`);
  }

  if (collection.status === "fulfilled") {
    renderCollection(collection.value);
  } else {
    setValue("#home-collection-state", "Indisponible");
    setValue("#home-collection-details", collection.reason.message);
  }
  refreshButton.disabled = false;
}

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = setupForm.querySelector("button[type=submit]");
  const errorMessage = document.querySelector("#setup-error");
  button.disabled = true;
  errorMessage.textContent = "";
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
  const button = loginForm.querySelector("button[type=submit]");
  button.disabled = true;
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
    sessionStorage.setItem(sessionKey, result.token);
    document.querySelector("#password").value = "";
    await refreshHome();
  } catch (error) {
    errorMessage.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#refresh-home").addEventListener("click", refreshHome);
document.querySelector("#logout").addEventListener("click", async () => {
  const token = sessionStorage.getItem(sessionKey);
  try {
    if (token) {
      const response = await fetch("/api/auth/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error(`Erreur HTTP ${response.status}`);
    }
    sessionStorage.removeItem(sessionKey);
    menu.open = false;
    showLogin();
  } catch (error) {
    setValue("#home-error", `Impossible de fermer la session côté serveur : ${error.message}`);
  }
});

async function initializeHome() {
  try {
    const response = await fetch("/api/setup/status", { cache: "no-store" });
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || `Erreur HTTP ${response.status}`);
    if (status.required) {
      sessionStorage.removeItem(sessionKey);
      setupPanel.hidden = false;
      return;
    }
    if (sessionStorage.getItem(sessionKey)) {
      loginPanel.hidden = true;
      await refreshHome();
    } else {
      showLogin();
    }
  } catch (error) {
    showLogin(error.message);
  }
}

initializeHome();
