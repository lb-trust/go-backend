"use strict";

const sessionKey = "soc-admin-session";
const sessionToken = sessionStorage.getItem(sessionKey);

if (!sessionToken) {
  window.location.replace("/");
}

async function adminAPI(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${sessionToken || ""}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  if (response.status === 401) {
    sessionStorage.removeItem(sessionKey);
    window.location.replace("/");
    throw new Error("Session expirée ; reconnectez-vous.");
  }
  if (response.status === 204) return null;
  const responseText = await response.text();
  const result = responseText ? JSON.parse(responseText) : null;
  if (!response.ok) {
    throw new Error((result && result.error) || `Erreur HTTP ${response.status}`);
  }
  return result;
}

function showMessage(element, message, success = false) {
  element.textContent = message;
  element.classList.toggle("success-message", success);
}

function bindPasswordConfirmation(password, confirmation, message) {
  const validate = () => {
    const mismatch = confirmation.value !== "" && confirmation.value !== password.value;
    const error = "Les deux mots de passe ne correspondent pas.";
    confirmation.setCustomValidity(mismatch ? error : "");
    showMessage(message, mismatch ? error : "");
  };
  password.addEventListener("input", validate);
  confirmation.addEventListener("input", validate);
  return validate;
}

async function loadAccounts() {
  const error = document.querySelector("#accounts-error");
  const list = document.querySelector("#accounts-list");
  try {
    const [accounts, current] = await Promise.all([
      adminAPI("/api/admin/accounts"),
      adminAPI("/api/auth/me"),
    ]);
    list.replaceChildren();
    for (const account of accounts) {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      name.textContent = account.username;
      const role = document.createElement("td");
      role.textContent = account.role === "admin" ? "Administrateur" : account.role;
      const action = document.createElement("td");
      if (account.username !== current.username) {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "danger-button row-action";
        remove.textContent = "Supprimer";
        remove.addEventListener("click", async () => {
          if (!window.confirm(`Supprimer le compte « ${account.username} » ?`)) return;
          try {
            await adminAPI(`/api/admin/accounts/${encodeURIComponent(account.username)}`, {
              method: "DELETE",
            });
            await loadAccounts();
          } catch (requestError) {
            showMessage(error, requestError.message);
          }
        });
        action.append(remove);
      } else {
        action.textContent = "Compte actuel";
      }
      row.append(name, role, action);
      list.append(row);
    }
    showMessage(error, "");
  } catch (requestError) {
    showMessage(error, requestError.message);
  }
}

const createAccountForm = document.querySelector("#create-account-form");
if (createAccountForm) {
  const validateCreatePassword = bindPasswordConfirmation(
    document.querySelector("#new-password"),
    document.querySelector("#confirm-new-password"),
    document.querySelector("#create-password-mismatch"),
  );
  loadAccounts();
  createAccountForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = document.querySelector("#create-account-message");
    try {
      await adminAPI("/api/admin/accounts", {
        method: "POST",
        body: JSON.stringify({
          username: document.querySelector("#new-username").value.trim(),
          password: document.querySelector("#new-password").value,
          confirm_password: document.querySelector("#confirm-new-password").value,
        }),
      });
      createAccountForm.reset();
      validateCreatePassword();
      showMessage(message, "Compte administrateur créé.", true);
      await loadAccounts();
    } catch (error) {
      showMessage(message, error.message);
    }
  });

  const changePasswordForm = document.querySelector("#change-password-form");
  bindPasswordConfirmation(
    document.querySelector("#new-account-password"),
    document.querySelector("#confirm-account-password"),
    document.querySelector("#change-password-mismatch"),
  );
  changePasswordForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = document.querySelector("#password-message");
    try {
      await adminAPI("/api/admin/password", {
        method: "PATCH",
        body: JSON.stringify({
          current_password: document.querySelector("#current-account-password").value,
          new_password: document.querySelector("#new-account-password").value,
          confirm_new_password: document.querySelector("#confirm-account-password").value,
        }),
      });
      sessionStorage.setItem("soc-password-changed", "true");
      sessionStorage.removeItem(sessionKey);
      window.location.replace("/");
    } catch (error) {
      showMessage(message, error.message);
    }
  });
}

const wazuhForm = document.querySelector("#wazuh-form");
if (wazuhForm) {
  const message = document.querySelector("#wazuh-config-message");
  const clearButton = document.querySelector("#clear-wazuh");
  const infoControls = [...document.querySelectorAll(".field-help-control")];

  function closeInfo(control) {
    control.querySelector(".info-toggle").setAttribute("aria-expanded", "false");
    control.querySelector(".field-help").hidden = true;
  }

  infoControls.forEach((control) => {
    const button = control.querySelector(".info-toggle");
    const help = control.querySelector(".field-help");
    button.addEventListener("click", () => {
      const shouldOpen = button.getAttribute("aria-expanded") !== "true";
      infoControls.forEach(closeInfo);
      if (shouldOpen) {
        button.setAttribute("aria-expanded", "true");
        help.hidden = false;
      }
    });
  });

  document.addEventListener("click", (event) => {
    infoControls.forEach((control) => {
      const button = control.querySelector(".info-toggle");
      const help = control.querySelector(".field-help");
      if (!button.contains(event.target) && !help.contains(event.target)) closeInfo(control);
    });
  });

  document.addEventListener("focusin", (event) => {
    infoControls.forEach((control) => {
      if (!control.contains(event.target)) closeInfo(control);
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const openControl = infoControls.find(
      (control) => control.querySelector(".info-toggle").getAttribute("aria-expanded") === "true",
    );
    if (openControl) {
      closeInfo(openControl);
      openControl.querySelector(".info-toggle").focus();
    }
  });

  async function loadWazuhConfiguration() {
    try {
      const configuration = await adminAPI("/api/admin/wazuh");
      if (configuration.configured) {
        document.querySelector("#wazuh-url").value = configuration.url;
        document.querySelector("#wazuh-username").value = configuration.username;
        document.querySelector("#wazuh-ignore-tls").checked = configuration.verify_tls === false;
        document.querySelector("#wazuh-index").value = configuration.alerts_index;
        document.querySelector("#wazuh-agents-index").value =
          configuration.agents_index || "wazuh-states-agents-*";
        document.querySelector("#wazuh-vulnerabilities-index").value =
          configuration.vulnerabilities_index || "wazuh-states-vulnerabilities-*";
        document.querySelector("#wazuh-batch-size").value = configuration.batch_size;
        document.querySelector("#wazuh-password").placeholder = configuration.password_configured
          ? "Laisser vide pour conserver le mot de passe"
          : "";
        clearButton.hidden = false;
      }
    } catch (error) {
      showMessage(message, error.message);
      document.querySelector("#save-wazuh").disabled = true;
    }
  }

  loadWazuhConfiguration();
  wazuhForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const saveButton = document.querySelector("#save-wazuh");
    saveButton.disabled = true;
    showMessage(message, "Test de connexion à Wazuh en cours…");
    try {
      await adminAPI("/api/admin/wazuh", {
        method: "PUT",
        body: JSON.stringify({
          url: document.querySelector("#wazuh-url").value.trim(),
          username: document.querySelector("#wazuh-username").value.trim(),
          password: document.querySelector("#wazuh-password").value,
          verify_tls: !document.querySelector("#wazuh-ignore-tls").checked,
          alerts_index: document.querySelector("#wazuh-index").value.trim(),
          agents_index: document.querySelector("#wazuh-agents-index").value.trim(),
          vulnerabilities_index: document.querySelector("#wazuh-vulnerabilities-index").value.trim(),
          batch_size: Number(document.querySelector("#wazuh-batch-size").value),
        }),
      });
      document.querySelector("#wazuh-password").value = "";
      document.querySelector("#wazuh-password").placeholder = "Laisser vide pour conserver le mot de passe";
      clearButton.hidden = false;
      showMessage(message, "Connexion réussie ; configuration enregistrée.", true);
    } catch (error) {
      showMessage(message, error.message);
    } finally {
      saveButton.disabled = false;
    }
  });

  clearButton.addEventListener("click", async () => {
    if (!window.confirm("Supprimer la configuration Wazuh ? La collecte sera arrêtée.")) return;
    try {
      await adminAPI("/api/admin/wazuh", { method: "DELETE" });
      wazuhForm.reset();
      document.querySelector("#wazuh-index").value = "wazuh-alerts-*";
      document.querySelector("#wazuh-agents-index").value = "wazuh-states-agents-*";
      document.querySelector("#wazuh-vulnerabilities-index").value = "wazuh-states-vulnerabilities-*";
      document.querySelector("#wazuh-batch-size").value = "100";
      document.querySelector("#wazuh-ignore-tls").checked = false;
      clearButton.hidden = true;
      showMessage(message, "Configuration Wazuh supprimée.", true);
    } catch (error) {
      showMessage(message, error.message);
    }
  });
}

const clearAlertsForm = document.querySelector("#clear-alerts-form");
if (clearAlertsForm) {
  const message = document.querySelector("#clear-alerts-message");
  const loading = document.querySelector("#clear-alerts-loading");
  clearAlertsForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!window.confirm(
      "Supprimer définitivement toutes les alertes de tous les clients ainsi que leurs incidents et analyses ? Cette action est irréversible.",
    )) return;

    const button = clearAlertsForm.querySelector("button[type='submit']");
    button.disabled = true;
    clearAlertsForm.setAttribute("aria-busy", "true");
    loading.hidden = false;
    showMessage(message, "");
    try {
      await adminAPI("/api/admin/alerts", {
        method: "DELETE",
        body: JSON.stringify({
          current_password: document.querySelector("#clear-alerts-password").value,
        }),
      });
      clearAlertsForm.reset();
      showMessage(message, "Toutes les alertes et les données associées ont été supprimées. Le système est réinitialisé.", true);
    } catch (error) {
      showMessage(message, error.message);
    } finally {
      document.querySelector("#clear-alerts-password").value = "";
      loading.hidden = true;
      clearAlertsForm.setAttribute("aria-busy", "false");
      button.disabled = false;
    }
  });
}
