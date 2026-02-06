/* ---------------------------------------------------------------------------
 * Author  : Kyle <kyle@hacking-linux.com>
 * Version : 20260206v1
 * --------------------------------------------------------------------------- */
/**
 * app.js – Single JavaScript file for the Password Manager frontend.
 *
 * Sections
 * --------
 * 1.  Configuration & token management
 * 2.  API layer (Fetch wrapper)
 * 3.  Toast & error helpers
 * 4.  Login page  – initLoginPage()
 * 5.  Vault page  – initVaultPage()
 * 6.  Admin page  – initAdminPage()
 * 7.  Password generator (JS-side fallback using crypto.getRandomValues)
 *
 * Security notes
 * --------------
 * • The JWT is stored in sessionStorage (cleared on tab close).  For
 *   production replace with an httpOnly cookie set by the backend.
 * • Vault passwords are never stored client-side; they arrive only via
 *   the /decrypt endpoint when the user clicks "Reveal".
 */

// ==========================================================================
// 1.  Configuration & token management
// ==========================================================================

const BASE_URL = "";  // API is served from the same origin

// In-memory cache; survives page navigation within the same tab.
let _token  = sessionStorage.getItem("pm_token") || null;
let _role   = sessionStorage.getItem("pm_role")  || null;

function setToken(token, role) {
  _token = token;
  _role  = role;
  sessionStorage.setItem("pm_token", token);
  sessionStorage.setItem("pm_role",  role);
}

function getToken()  { return _token; }
function getRole()   { return _role; }

function clearToken() {
  _token = null;
  _role  = null;
  sessionStorage.removeItem("pm_token");
  sessionStorage.removeItem("pm_role");
}

// ==========================================================================
// 2.  API layer
// ==========================================================================

/**
 * Thin Fetch wrapper.
 *   method – GET | POST | PUT | DELETE
 *   path   – e.g. "/auth/login"
 *   body   – object (will be JSON-serialised) or null
 *
 * On 401 the token is cleared and the browser is redirected to login.
 * Returns the parsed JSON response (or undefined for 204).
 */
async function apiCall(method, path, body = null) {
  const headers = { "Content-Type": "application/json" };
  if (getToken()) headers["Authorization"] = "Bearer " + getToken();

  const opts = { method, headers };
  if (body !== null) opts.body = JSON.stringify(body);

  const res = await fetch(BASE_URL + path, opts);

  // Automatic logout on 401
  if (res.status === 401) {
    clearToken();
    window.location.href = "login.html";
    return;                          // stop execution
  }

  if (res.status === 204) return;    // no body

  const json = await res.json();

  if (!res.ok) {
    // Throw an error that carries the server's detail message
    const err = new Error(json.detail || "Server error");
    err.status = res.status;
    throw err;
  }

  return json;
}

// ==========================================================================
// 3.  Toast & error helpers
// ==========================================================================

let _toastTimer = null;

/**
 * Show a toast notification.
 *   message – text to display
 *   type    – "success" | "error"
 */
function showToast(message, type = "success") {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = message;
  el.className   = "toast " + type + " visible";
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.classList.remove("visible"); }, 3200);
}

/**
 * Show / hide an inline error message element.
 */
function showError(elementId, message) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.classList.add("visible");
}

function clearError(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.classList.remove("visible");
}

// ==========================================================================
// 4.  Login page
// ==========================================================================

function initLoginPage() {
  const loginForm = document.getElementById("login-form");
  const cpForm    = document.getElementById("cp-form");

  // -- Login form submit -----------------------------------------------
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError("login-error");

    const email    = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;

    try {
      const data = await apiCall("POST", "/auth/login", { email, password });

      // Store token + role
      setToken(data.access_token, "unknown"); // role fetched via /me below

      if (data.force_password_change) {
        // Show the mandatory password-change modal
        document.getElementById("cp-modal").classList.add("visible");
        return;
      }

      // Fetch role and redirect
      const me = await apiCall("GET", "/auth/me");
      setToken(data.access_token, me.role);
      window.location.href = "vault.html";

    } catch (err) {
      showError("login-error", err.message);
    }
  });

  // -- Change-password form (modal) ------------------------------------
  cpForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError("cp-error");

    const oldPw  = document.getElementById("cp-old").value;
    const newPw  = document.getElementById("cp-new").value;
    const confirm = document.getElementById("cp-confirm").value;

    if (newPw !== confirm) {
      showError("cp-error", "Passwords do not match");
      return;
    }

    try {
      await apiCall("PUT", "/auth/change-password", {
        old_password: oldPw,
        new_password: newPw,
      });

      // Fetch role and navigate
      const me = await apiCall("GET", "/auth/me");
      setToken(getToken(), me.role);
      window.location.href = "vault.html";

    } catch (err) {
      showError("cp-error", err.message);
    }
  });
}

// ==========================================================================
// 5.  Vault page
// ==========================================================================

// Module-level state for the vault page
let _items       = [];          // current list from server
let _currentId   = null;        // null = "new entry" mode; number = editing existing
let _passwordVis = false;       // tracks reveal state

// Category icons shown in the sidebar
const _CAT_ICONS = {
  login:          "🔑",
  ssh_key:        "🗝️",
  api_credential: "🔧",
  database:       "🗄️",
};

// Category-specific field labels
const _CAT_LABELS = {
  login:          { username: "Username", password: "Password", url: "URL (optional)" },
  ssh_key:        { username: "Username", password: "Password", url: "Hostname" },
  api_credential: { password: "API Key", url: "Endpoint URL (optional)" },
  database:       { username: "Username", password: "Password", url: "Connection String / Host" },
};

function updateFieldVisibility() {
  const category = document.getElementById("item-category").value;
  const labels = _CAT_LABELS[category] || _CAT_LABELS.login;

  // Get all conditional fields and buttons
  const fields = document.querySelectorAll("[data-categories], [data-show-for]");

  fields.forEach((field) => {
    const allowedCategories = (field.dataset.categories || field.dataset.showFor || "").split(",");
    const isVisible = allowedCategories.includes(category);
    field.style.display = isVisible ? "" : "none";

    // Update required attribute on inputs inside this field
    const input = field.querySelector("input, textarea");
    if (input && input.id !== "item-password") {
      // Password required logic is handled separately based on category
      input.required = isVisible && (category !== "secure_note");
    }
  });

  // Update labels
  const labelUsername = document.getElementById("label-username");
  const labelPassword = document.getElementById("label-password");
  const labelUrl = document.getElementById("label-url");

  if (labelUsername) labelUsername.textContent = labels.username || "Username";
  if (labelPassword) labelPassword.textContent = labels.password || "Password";
  if (labelUrl) labelUrl.textContent = labels.url || "URL (optional)";

  // Password is required only for login and database
  const passwordInput = document.getElementById("item-password");
  if (passwordInput) {
    passwordInput.required = (category === "login" || category === "database");
  }

  // Hide the password generator panel when category changes
  const genPanel = document.getElementById("gen-panel");
  if (genPanel && genPanel.classList.contains("visible")) {
    genPanel.classList.remove("visible");
  }
}

function initVaultPage() {
  // Guard – must be logged in
  if (!getToken()) { window.location.href = "login.html"; return; }

  // Populate header and check role
  apiCall("GET", "/auth/me").then((me) => {
    document.getElementById("logged-in-email").textContent = me.email;
    if (me.role === "admin") {
      document.getElementById("admin-nav-dropdown").style.display = "block";
    }
  }).catch(() => { window.location.href = "login.html"; });

  // Load items
  loadItems();

  // -- Wire up buttons -----------------------------------------------
  document.getElementById("logout-btn").addEventListener("click", logout);
  document.getElementById("add-item-btn").addEventListener("click", openNewForm);
  document.getElementById("cancel-btn").addEventListener("click", closeDetailPanel);
  document.getElementById("delete-btn").addEventListener("click", deleteItem);
  document.getElementById("copy-password-btn").addEventListener("click", copyPassword);
  document.getElementById("reveal-btn").addEventListener("click", revealPassword);

  // Generator toggle
  document.getElementById("gen-toggle-btn").addEventListener("click", () => {
    document.getElementById("gen-panel").classList.toggle("visible");
  });

  // Category selector – show/hide fields based on type
  document.getElementById("item-category").addEventListener("change", updateFieldVisibility);

  // Mode radio buttons control which option rows are visible
  document.querySelectorAll('input[name="gen-mode"]').forEach((radio) => {
    radio.addEventListener("change", updateGenUI);
  });

  document.getElementById("gen-go-btn").addEventListener("click", generatePassword);

  // Sidebar search – live-filter the item list as the user types
  document.getElementById("search-input").addEventListener("input", renderItemList);

  // Export / Import
  document.getElementById("export-btn").addEventListener("click", exportVault);
  document.getElementById("import-btn").addEventListener("click", () => {
    document.getElementById("import-file-input").click();
  });
  document.getElementById("import-file-input").addEventListener("change", importVault);

  // Form submit
  document.getElementById("item-form").addEventListener("submit", saveItem);
}

// -- Data loading ----------------------------------------------------------

async function loadItems() {
  try {
    const data = await apiCall("GET", "/vault/items");
    _items = data.items || [];
    renderItemList();
  } catch (err) {
    showToast("Failed to load items: " + err.message, "error");
  }
}

function renderItemList() {
  const ul   = document.getElementById("item-list");
  ul.innerHTML = "";

  // -- live search filter ----------------------------------------------
  // Normalise to lower-case for a simple case-insensitive substring match.
  // Matches against title, username, url, and notes so every text field is searchable.
  const query = (document.getElementById("search-input")?.value || "").trim().toLowerCase();
  const visible = query
    ? _items.filter((it) => {
        const haystack = [it.title, it.username, it.url, it.notes]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(query);
      })
    : _items;
  // --------------------------------------------------------------------

  if (visible.length === 0) {
    ul.innerHTML = query
      ? '<li class="sidebar-empty">No matches</li>'
      : '<li class="sidebar-empty">No entries yet</li>';
    return;
  }

  visible.forEach((item) => {
    const li = document.createElement("li");
    li.dataset.id = item.id;
    li.innerHTML = `
      <div class="item-title-row">
        <span class="cat-icon cat-${escapeHtml(item.category || "login")}">${_CAT_ICONS[item.category] || _CAT_ICONS.login}</span>
        <span class="item-title">${escapeHtml(item.title)}</span>
      </div>
      <div class="item-url">${escapeHtml(item.url || item.username)}</div>
    `;
    li.addEventListener("click", () => selectItem(item.id));
    ul.appendChild(li);
  });
}

// -- Form helpers ----------------------------------------------------------

function openNewForm() {
  _currentId = null;
  _passwordVis = false;

  document.getElementById("detail-heading").textContent = "New Entry";
  document.getElementById("item-category").value  = "login";
  document.getElementById("item-title").value    = "";
  document.getElementById("item-username").value = "";
  document.getElementById("item-password").value = "";
  document.getElementById("item-password").type  = "password";
  document.getElementById("item-url").value      = "";
  document.getElementById("item-port").value     = "";
  document.getElementById("item-private-key").value = "";
  document.getElementById("item-public-key").value = "";
  document.getElementById("item-api-key").value = "";
  document.getElementById("item-api-secret").value = "";
  document.getElementById("item-notes").value    = "";
  document.getElementById("delete-btn").style.display = "none";
  document.getElementById("reveal-btn").textContent   = "👁 Reveal";

  updateFieldVisibility();  // Show/hide fields based on category

  showDetailPanel();
  clearError("item-error");
}

async function selectItem(id) {
  const item = _items.find((i) => i.id === id);
  if (!item) return;

  _currentId   = id;
  _passwordVis = false;

  // Highlight in sidebar
  document.querySelectorAll(".item-list li").forEach((li) => li.classList.remove("active"));
  const active = document.querySelector(`.item-list li[data-id="${id}"]`);
  if (active) active.classList.add("active");

  // Fill form – password is left blank until explicitly loaded
  document.getElementById("detail-heading").textContent = "Edit Entry";
  document.getElementById("item-category").value  = item.category || "login";
  document.getElementById("item-title").value    = item.title;
  document.getElementById("item-username").value = item.username;
  document.getElementById("item-password").value = "";
  document.getElementById("item-password").type  = "password";
  document.getElementById("item-url").value      = item.url || "";
  document.getElementById("item-port").value     = item.port || "";
  document.getElementById("item-private-key").value = item.private_key || "";
  document.getElementById("item-public-key").value = item.public_key || "";
  document.getElementById("item-api-key").value = item.api_key || "";
  document.getElementById("item-api-secret").value = "";
  document.getElementById("item-notes").value    = item.notes || "";
  document.getElementById("delete-btn").style.display = "inline-flex";
  document.getElementById("reveal-btn").textContent   = "👁 Reveal";

  updateFieldVisibility();  // Show/hide fields based on category

  showDetailPanel();
  clearError("item-error");

  // For API credentials, auto-load the api_secret
  if (item.category === "api_credential") {
    console.log("Loading API Secret for item", id);
    try {
      const data = await apiCall("GET", `/vault/items/${id}/decrypt`);
      console.log("Decrypt response:", data);
      const secretValue = data.plaintext_api_secret;
      console.log("plaintext_api_secret value:", secretValue, "type:", typeof secretValue);

      const field = document.getElementById("item-api-secret");
      console.log("Field before set:", field, "current value:", field.value);

      if (secretValue !== null && secretValue !== undefined) {
        field.value = secretValue;
        console.log("Field after set:", field.value);
      } else {
        console.log("plaintext_api_secret is null or undefined, not setting");
      }
    } catch (err) {
      console.error("Failed to load API Secret:", err);
    }
  }
}

function showDetailPanel() {
  document.getElementById("detail-panel").style.display = "block";
  document.getElementById("empty-state").style.display  = "none";
}

function closeDetailPanel() {
  _currentId = null;
  document.getElementById("detail-panel").style.display = "none";
  document.getElementById("empty-state").style.display  = "block";
  document.querySelectorAll(".item-list li").forEach((li) => li.classList.remove("active"));
}

// -- Copy password ---------------------------------------------------------

async function copyPassword() {
  const input = document.getElementById("item-password");

  // If password is not visible and we have a saved item, fetch it first
  if (!_passwordVis && _currentId) {
    try {
      const data = await apiCall("GET", `/vault/items/${_currentId}/decrypt`);
      await navigator.clipboard.writeText(data.plaintext_password);
      showToast("Password copied to clipboard", "success");
    } catch (err) {
      showError("item-error", "Failed to copy: " + err.message);
    }
  } else {
    // Password is visible or it's a new item - just copy what's in the field
    const password = input.value;
    if (!password) {
      showToast("No password to copy", "error");
      return;
    }
    try {
      await navigator.clipboard.writeText(password);
      showToast("Password copied to clipboard", "success");
    } catch (err) {
      showToast("Failed to copy to clipboard", "error");
    }
  }
}

// -- Reveal / hide password toggle ----------------------------------------
// Single handler bound once via addEventListener.  Toggling is driven by
// the _passwordVis flag – no onclick swapping needed.

async function revealPassword() {
  const input = document.getElementById("item-password");
  const btn   = document.getElementById("reveal-btn");

  // -- HIDE path -------------------------------------------------------
  if (_passwordVis) {
    // If there's no saved item, just hide what's typed; don't clear it
    if (!_currentId) {
      input.type = "password";
      _passwordVis = false;
      btn.textContent = "👁 Reveal";
      return;
    }
    // For saved items, clear and hide
    input.value  = "";
    input.type   = "password";
    _passwordVis = false;
    btn.textContent = "👁 Reveal";
    return;
  }

  // -- REVEAL path -----------------------------------------------------
  // If no saved item, just toggle visibility of what's typed
  if (!_currentId) {
    input.type = "text";
    _passwordVis = true;
    btn.textContent = "🔒 Hide";
    return;
  }

  // For saved items, fetch from server
  clearError("item-error");
  try {
    const data = await apiCall("GET", `/vault/items/${_currentId}/decrypt`);
    input.value  = data.plaintext_password;
    input.type   = "text";
    _passwordVis = true;
    btn.textContent = "🔒 Hide";
  } catch (err) {
    showError("item-error", "Failed to decrypt: " + err.message);
  }
}

// -- Save (create / update) ------------------------------------------------

async function saveItem(e) {
  e.preventDefault();
  clearError("item-error");

  const category = document.getElementById("item-category").value;
  const title    = document.getElementById("item-title").value.trim();
  const username = document.getElementById("item-username").value.trim();
  const password = document.getElementById("item-password").value;
  const url      = document.getElementById("item-url").value.trim() || null;
  const portStr  = document.getElementById("item-port").value.trim();
  const port     = portStr ? parseInt(portStr, 10) : null;
  const privateKey = document.getElementById("item-private-key").value.trim() || null;
  const publicKey = document.getElementById("item-public-key").value.trim() || null;
  const apiKey = document.getElementById("item-api-key").value.trim() || null;
  const apiSecret = document.getElementById("item-api-secret").value.trim() || null;
  const notes    = document.getElementById("item-notes").value.trim() || null;

  // Validation: title is always required
  if (!title) {
    showError("item-error", "Title is required");
    return;
  }

  try {
    if (_currentId === null) {
      // -- CREATE --
      // Password is required for login and database
      if ((category === "login" || category === "database") && !password) {
        showError("item-error", "Password is required");
        return;
      }
      await apiCall("POST", "/vault/items", {
        category, title, username: username || "", plaintext_password: password || "", url, port, private_key: privateKey, public_key: publicKey, api_key: apiKey, plaintext_api_secret: apiSecret, notes,
      });
      showToast("Entry created");
    } else {
      // -- UPDATE --
      const body = { category, title, username: username || "", url, port, private_key: privateKey, public_key: publicKey, notes };
      if (password) body.plaintext_password = password;
      if (apiKey) body.api_key = apiKey;
      if (apiSecret) body.plaintext_api_secret = apiSecret;
      await apiCall("PUT", `/vault/items/${_currentId}`, body);
      showToast("Entry updated");
    }

    // Refresh list and close form
    await loadItems();
    closeDetailPanel();

  } catch (err) {
    showError("item-error", err.message);
  }
}

// -- Delete ----------------------------------------------------------------

async function deleteItem() {
  if (_currentId === null) return;
  if (!window.confirm("Delete this entry permanently?")) return;
  clearError("item-error");

  try {
    await apiCall("DELETE", `/vault/items/${_currentId}`);
    showToast("Entry deleted", "error");
    await loadItems();
    closeDetailPanel();
  } catch (err) {
    showError("item-error", err.message);
  }
}

// -- Export vault → Excel --------------------------------------------------

async function exportVault() {
  try {
    const headers = { "Content-Type": "application/json" };
    if (getToken()) headers["Authorization"] = "Bearer " + getToken();

    const res = await fetch("/vault/export", { method: "GET", headers });

    if (res.status === 401) { clearToken(); window.location.href = "login.html"; return; }
    if (!res.ok) {
      const json = await res.json();
      throw new Error(json.detail || "Export failed");
    }

    // Trigger browser download from the blob
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = "passwords.xlsx";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast("Passwords exported as passwords.xlsx", "success");
  } catch (err) {
    showToast("Export failed: " + err.message, "error");
  }
}

// -- Import vault ← Excel --------------------------------------------------

async function importVault(e) {
  const file = e.target.files?.[0];
  if (!file) return;

  // Reset the file input so selecting the same file again will trigger change
  e.target.value = "";

  if (!file.name.toLowerCase().endsWith(".xlsx")) {
    showToast("Only .xlsx files are supported", "error");
    return;
  }

  try {
    const formData = new FormData();
    formData.append("file", file);

    const headers = {};
    if (getToken()) headers["Authorization"] = "Bearer " + getToken();

    const res = await fetch("/vault/import", {
      method: "POST",
      headers,
      body: formData,
    });

    if (res.status === 401) { clearToken(); window.location.href = "login.html"; return; }

    const json = await res.json();
    if (!res.ok) throw new Error(json.detail || "Import failed");

    // Build a summary message
    let msg = `Import complete: ${json.imported} added`;
    if (json.skipped_duplicates > 0) msg += `, ${json.skipped_duplicates} duplicate(s) skipped`;
    if (json.skipped_invalid   > 0) msg += `, ${json.skipped_invalid} invalid row(s) skipped`;

    showToast(msg, "success");

    // Refresh the sidebar list
    await loadItems();
  } catch (err) {
    showToast("Import failed: " + err.message, "error");
  }
}

// -- Generator UI helpers --------------------------------------------------

function updateGenUI() {
  const mode = document.querySelector('input[name="gen-mode"]:checked').value;
  document.getElementById("gen-random-opts").style.display = (mode === "random") ? "flex" : "none";
}

/**
 * Primary: call the backend generator.  Fallback: generate locally with
 * crypto.getRandomValues if the network call fails.
 */
async function generatePassword() {
  const mode = document.querySelector('input[name="gen-mode"]:checked').value;

  // All modes now use the same length input
  const length = parseInt(document.getElementById("gen-length-input").value, 10) || 16;
  const includeDigits = document.getElementById("gen-digits").checked;
  const includeSymbols = document.getElementById("gen-symbols").checked;

  try {
    const params = new URLSearchParams({ mode, length });
    if (mode === "random") {
      params.set("include_digits", includeDigits);
      params.set("include_symbols", includeSymbols);
    }

    const data = await apiCall("GET", `/vault/generate-password?${params}`);
    document.getElementById("item-password").value = data.password;
    document.getElementById("item-password").type  = "text";
    _passwordVis = true;
    document.getElementById("reveal-btn").textContent = "🔒 Hide";

  } catch {
    // Fallback: generate entirely in the browser
    const pw = generatePasswordLocally(mode, length, {
      digits:  includeDigits,
      symbols: includeSymbols,
    });
    document.getElementById("item-password").value = pw;
    document.getElementById("item-password").type  = "text";
    _passwordVis = true;
    document.getElementById("reveal-btn").textContent = "🔒 Hide";
  }
}

// ==========================================================================
// 6.  Admin page
// ==========================================================================

// -- Create User page (admin.html) -----------------------------------------
function initCreateUserPage() {
  if (!getToken()) { window.location.href = "login.html"; return; }

  // Verify role; non-admins are bounced back to vault
  apiCall("GET", "/auth/me").then((me) => {
    if (me.role !== "admin") { window.location.href = "vault.html"; return; }
    document.getElementById("logged-in-email").textContent = me.email;
  }).catch(() => { window.location.href = "login.html"; });

  document.getElementById("logout-btn").addEventListener("click", logout);
  document.getElementById("create-user-form").addEventListener("submit", createUser);
}

// -- User Management page (admin-users.html) ------------------------------
let _currentAdminId = null;   // filled after /auth/me resolves

function initUserManagementPage() {
  if (!getToken()) { window.location.href = "login.html"; return; }

  // Verify role; non-admins are bounced back to vault
  apiCall("GET", "/auth/me").then((me) => {
    if (me.role !== "admin") { window.location.href = "vault.html"; return; }
    _currentAdminId = me.id;
    document.getElementById("logged-in-email").textContent = me.email;
    loadUsers();
  }).catch(() => { window.location.href = "login.html"; });

  document.getElementById("logout-btn").addEventListener("click", logout);

  // Reset-password modal
  document.getElementById("rp-form").addEventListener("submit", resetPassword);
  document.getElementById("rp-close").addEventListener("click", closeResetModal);

  // Change-role modal
  document.getElementById("cr-form").addEventListener("submit", changeRole);
  document.getElementById("cr-close").addEventListener("click", closeChangeRoleModal);

  // Delegate click events on action buttons – registered once here so it does
  // not stack up every time renderUserTable() re-renders the tbody.
  document.getElementById("user-tbody").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    const id     = parseInt(btn.dataset.id, 10);

    if (action === "reset")      openResetModal(id);
    if (action === "changerole") openChangeRoleModal(id, btn.dataset.email, btn.dataset.role);
    if (action === "disable")    disableUser(id);
    if (action === "enable")     enableUser(id);
  });
}

// -- Load & render users ---------------------------------------------------

async function loadUsers() {
  try {
    const data = await apiCall("GET", "/admin/users");
    renderUserTable(data.users || []);
  } catch (err) {
    showToast("Failed to load users: " + err.message, "error");
  }
}

function renderUserTable(users) {
  const tbody = document.getElementById("user-tbody");
  tbody.innerHTML = "";

  users.forEach((u) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${u.id}</td>
      <td>${escapeHtml(u.email)}</td>
      <td><span class="badge badge-${u.role}">${u.role}</span></td>
      <td><span class="badge ${u.is_active ? "badge-active" : "badge-inactive"}">${u.is_active ? "Active" : "Disabled"}</span></td>
      <td>${u.last_login ? new Date(u.last_login).toLocaleString() : '—'}</td>
      <td class="actions-cell">
        <button class="btn btn-secondary btn-sm" data-action="reset" data-id="${u.id}">Reset PW</button>
        ${u.id !== _currentAdminId
          ? `<button class="btn btn-secondary btn-sm" data-action="changerole" data-id="${u.id}" data-email="${escapeHtml(u.email)}" data-role="${u.role}">Role</button>`
          : ''}
        ${u.id !== _currentAdminId
          ? (u.is_active
              ? `<button class="btn btn-danger btn-sm" data-action="disable" data-id="${u.id}">Disable</button>`
              : `<button class="btn btn-primary btn-sm" data-action="enable" data-id="${u.id}">Enable</button>`)
          : ''}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// -- Create user -----------------------------------------------------------

async function createUser(e) {
  e.preventDefault();
  clearError("cu-error");

  const email    = document.getElementById("cu-email").value.trim();
  const password = document.getElementById("cu-password").value;
  const role     = document.getElementById("cu-role").value;

  try {
    await apiCall("POST", "/admin/users", { email, password, role });
    showToast("User created");
    document.getElementById("create-user-form").reset();
  } catch (err) {
    showError("cu-error", err.message);
  }
}

// -- Reset password modal --------------------------------------------------

function openResetModal(userId) {
  document.getElementById("rp-user-id").value  = userId;
  document.getElementById("rp-new").value      = "";
  document.getElementById("rp-confirm").value  = "";
  clearError("rp-error");
  document.getElementById("rp-modal").classList.add("visible");
}

function closeResetModal() {
  document.getElementById("rp-modal").classList.remove("visible");
}

async function resetPassword(e) {
  e.preventDefault();
  clearError("rp-error");

  const userId     = document.getElementById("rp-user-id").value;
  const newPassword = document.getElementById("rp-new").value;
  const confirm     = document.getElementById("rp-confirm").value;

  if (newPassword !== confirm) {
    showError("rp-error", "Passwords do not match");
    return;
  }

  try {
    await apiCall("PUT", `/admin/users/${userId}/reset-password`, { new_password: newPassword });
    showToast("Password reset");
    closeResetModal();
    await loadUsers();
  } catch (err) {
    showError("rp-error", err.message);
  }
}

// -- Disable user ----------------------------------------------------------

async function disableUser(userId) {
  if (!window.confirm("Disable this user? They will no longer be able to log in.")) return;

  try {
    await apiCall("PUT", `/admin/users/${userId}/disable`);
    showToast("User disabled", "error");
    await loadUsers();
  } catch (err) {
    showToast(err.message, "error");
  }
}

// -- Enable user -----------------------------------------------------------

async function enableUser(userId) {
  try {
    await apiCall("PUT", `/admin/users/${userId}/enable`);
    showToast("User enabled");
    await loadUsers();
  } catch (err) {
    showToast(err.message, "error");
  }
}

// -- Change role modal -----------------------------------------------------

function openChangeRoleModal(userId, email, currentRole) {
  document.getElementById("cr-user-id").value = userId;
  document.getElementById("cr-email").textContent = email;
  document.getElementById("cr-role").value = currentRole;
  clearError("cr-error");
  document.getElementById("cr-modal").classList.add("visible");
}

function closeChangeRoleModal() {
  document.getElementById("cr-modal").classList.remove("visible");
}

async function changeRole(e) {
  e.preventDefault();
  clearError("cr-error");

  const userId = document.getElementById("cr-user-id").value;
  const role    = document.getElementById("cr-role").value;

  try {
    await apiCall("PUT", `/admin/users/${userId}/change-role`, { role });
    showToast("Role updated");
    closeChangeRoleModal();
    await loadUsers();
  } catch (err) {
    showError("cr-error", err.message);
  }
}

// -- Audit Log page (admin-audit.html) -------------------------------------

function initAuditPage() {
  if (!getToken()) { window.location.href = "login.html"; return; }

  apiCall("GET", "/auth/me").then((me) => {
    if (me.role !== "admin") { window.location.href = "vault.html"; return; }
    document.getElementById("logged-in-email").textContent = me.email;
  }).catch(() => { window.location.href = "login.html"; });

  document.getElementById("logout-btn").addEventListener("click", logout);
  document.getElementById("af-search-btn").addEventListener("click", fetchAuditLogs);
  document.getElementById("af-clear-btn").addEventListener("click", clearAuditFilters);
  document.getElementById("export-audit-btn").addEventListener("click", exportAuditLogs);

  // -- Sortable table headers --------------------------------------------
  document.querySelectorAll(".sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const column = th.dataset.column;
      if (_auditSortColumn === column) {
        _auditSortAsc = !_auditSortAsc;  // Toggle direction
      } else {
        _auditSortColumn = column;
        _auditSortAsc = true;  // Default ascending for new column
      }
      renderAuditTable(_auditLogs);  // Re-render with new sort
    });
    th.style.cursor = "pointer";
  });

  // -- Multi-select dropdown wiring --------------------------------------
  document.getElementById("af-ms-trigger").addEventListener("click", (e) => {
    e.stopPropagation();
    _msToggle();
  });

  // "Select all" checkbox
  document.getElementById("af-ms-all").addEventListener("change", (e) => {
    document.querySelectorAll(".ms-item input[type='checkbox']").forEach((cb) => {
      cb.checked = e.target.checked;
    });
    _msUpdateLabel();
  });

  // Close dropdown when clicking outside
  document.addEventListener("click", (e) => {
    const wrap = document.getElementById("af-ms-wrap");
    if (!wrap.contains(e.target)) _msClose();
    _dtCloseAll(e);
  });

  // -- Custom date-time pickers ------------------------------------------
  _dtSince = _dtCreatePicker("since", { hasNow: false });
  _dtUntil = _dtCreatePicker("until", { hasNow: true  });

  // Load the user list into the dropdown, then do the initial data fetch
  _msLoadUsers().then(() => fetchAuditLogs());
}

// -- Multi-select helpers --------------------------------------------------

async function _msLoadUsers() {
  try {
    const data = await apiCall("GET", "/admin/users");
    const list = document.getElementById("af-ms-list");
    list.innerHTML = "";
    (data.users || []).forEach((u) => {
      const label = document.createElement("label");
      label.className = "ms-item";
      label.innerHTML = `<input type="checkbox" value="${escapeHtml(u.email)}" /><span class="ms-email">${escapeHtml(u.email)}</span>`;
      // bubble label click → update the summary label
      label.addEventListener("change", () => {
        _msUpdateAll();
        _msUpdateLabel();
      });
      list.appendChild(label);
    });
  } catch (err) {
    showToast("Failed to load users: " + err.message, "error");
  }
}

function _msToggle() {
  const dropdown = document.getElementById("af-ms-dropdown");
  const trigger  = document.getElementById("af-ms-trigger");
  const isOpen   = dropdown.classList.contains("visible");
  if (isOpen) { _msClose(); } else { dropdown.classList.add("visible"); trigger.classList.add("open"); }
}

function _msClose() {
  document.getElementById("af-ms-dropdown").classList.remove("visible");
  document.getElementById("af-ms-trigger").classList.remove("open");
}

/** Keep "Select all" in sync when individual boxes change. */
function _msUpdateAll() {
  const boxes = document.querySelectorAll(".ms-item input[type='checkbox']");
  const allChecked = boxes.length > 0 && [...boxes].every((cb) => cb.checked);
  document.getElementById("af-ms-all").checked = allChecked;
}

/** Update the trigger label to reflect current selection. */
function _msUpdateLabel() {
  const checked = [...document.querySelectorAll(".ms-item input[type='checkbox']:checked")];
  const label   = document.getElementById("af-ms-label");
  if (checked.length === 0) {
    label.textContent = "Select users…";
  } else if (checked.length === 1) {
    label.textContent = checked[0].value;
  } else {
    label.textContent = checked[0].value + ` (+${checked.length - 1})`;
  }
}

/** Return array of currently checked email strings. */
function _msGetSelected() {
  return [...document.querySelectorAll(".ms-item input[type='checkbox']:checked")].map((cb) => cb.value);
}

// -- Custom date-time picker engine ---------------------------------------
// Each picker instance holds: { year, month, day, hh, mm } (day/hh/mm may be null)
// _dtSince / _dtUntil are module-level references set in initAuditPage().

let _dtSince = null, _dtUntil = null;
let _auditLogs = [];  // Store current audit logs for sorting/export

const _MONTHS = ["January","February","March","April","May","June",
                 "July","August","September","October","November","December"];

/**
 * Create and wire one picker.  `id` = "since" | "until".
 * Returns a state object with helper methods.
 */
function _dtCreatePicker(id, opts) {
  const now   = new Date();
  const state = {
    year: now.getFullYear(), month: now.getMonth(),  // always show current month initially
    day: null, hh: null, mm: null                    // nothing selected yet
  };

  const wrap    = document.getElementById("dt-" + id + "-wrap");
  const trigger = document.getElementById("dt-" + id + "-trigger");
  const pop     = document.getElementById("dt-" + id + "-pop");
  const display = document.getElementById("dt-" + id + "-display");
  const hhInput = document.getElementById("dt-" + id + "-hh");
  const mmInput = document.getElementById("dt-" + id + "-mm");

  // toggle open / close
  trigger.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = pop.classList.contains("visible");
    if (isOpen) { _dtClose(state); } else { _dtOpen(state); }
  });

  // month nav
  document.getElementById("dt-" + id + "-prev").addEventListener("click", () => {
    state.month--;
    if (state.month < 0) { state.month = 11; state.year--; }
    _dtRenderDays(state);
  });
  document.getElementById("dt-" + id + "-next").addEventListener("click", () => {
    state.month++;
    if (state.month > 11) { state.month = 0; state.year++; }
    _dtRenderDays(state);
  });

  // time input guards
  hhInput.addEventListener("input", () => {
    let v = parseInt(hhInput.value, 10);
    if (isNaN(v)) { state.hh = null; } else { state.hh = Math.min(23, Math.max(0, v)); hhInput.value = state.hh; }
    _dtUpdateDisplay(state);
  });
  mmInput.addEventListener("input", () => {
    let v = parseInt(mmInput.value, 10);
    if (isNaN(v)) { state.mm = null; } else { state.mm = Math.min(59, Math.max(0, v)); mmInput.value = state.mm; }
    _dtUpdateDisplay(state);
  });

  // footer buttons
  document.getElementById("dt-" + id + "-clear").addEventListener("click", () => {
    state.day = state.hh = state.mm = null;
    hhInput.value = ""; mmInput.value = "";
    _dtUpdateDisplay(state);
    _dtRenderDays(state);
  });
  document.getElementById("dt-" + id + "-today").addEventListener("click", () => {
    const t = new Date();
    state.year = t.getFullYear(); state.month = t.getMonth(); state.day = t.getDate();
    state.hh = state.mm = null;
    hhInput.value = ""; mmInput.value = "";
    _dtUpdateDisplay(state);
    _dtRenderDays(state);
  });
  if (opts.hasNow) {
    document.getElementById("dt-" + id + "-now").addEventListener("click", () => {
      const t = new Date();
      state.year = t.getFullYear(); state.month = t.getMonth(); state.day = t.getDate();
      state.hh = t.getHours(); state.mm = t.getMinutes();
      hhInput.value = String(state.hh).padStart(2, "0");
      mmInput.value = String(state.mm).padStart(2, "0");
      _dtUpdateDisplay(state);
      _dtRenderDays(state);
    });
  }

  // attach DOM refs to state so helpers can reach them
  state._pop     = pop;
  state._trigger = trigger;
  state._display = display;
  state._hhInput = hhInput;
  state._mmInput = mmInput;
  state._id      = id;

  return state;
}

function _dtOpen(state) {
  // close any other open picker first
  if (_dtSince && _dtSince !== state) _dtClose(_dtSince);
  if (_dtUntil && _dtUntil !== state) _dtClose(_dtUntil);
  state._pop.classList.add("visible");
  state._trigger.classList.add("open");
  _dtRenderDays(state);
}

function _dtClose(state) {
  state._pop.classList.remove("visible");
  state._trigger.classList.remove("open");
}

function _dtCloseAll(e) {
  // called on document click; close pickers whose wrap doesn't contain the target
  [_dtSince, _dtUntil].forEach((s) => {
    if (!s) return;
    const wrap = document.getElementById("dt-" + s._id + "-wrap");
    if (!wrap.contains(e.target)) _dtClose(s);
  });
}

/** Render the day-grid for the current month in state */
function _dtRenderDays(state) {
  const container = document.getElementById("dt-" + state._id + "-days");
  const monthLabel = document.getElementById("dt-" + state._id + "-month");
  monthLabel.textContent = _MONTHS[state.month] + " " + state.year;

  container.innerHTML = "";

  const firstDay  = new Date(state.year, state.month, 1).getDay();  // 0=Sun
  const daysInMonth = new Date(state.year, state.month + 1, 0).getDate();
  const today     = new Date();

  // blank cells before the 1st
  for (let i = 0; i < firstDay; i++) {
    container.appendChild(document.createElement("span"));  // empty placeholder
  }

  for (let d = 1; d <= daysInMonth; d++) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = d;
    if (d === today.getDate() && state.month === today.getMonth() && state.year === today.getFullYear()) {
      btn.classList.add("dt-today");
    }
    if (d === state.day) {
      btn.classList.add("dt-selected");
    }
    btn.addEventListener("click", () => {
      state.day = d;
      _dtRenderDays(state);
      _dtUpdateDisplay(state);
    });
    container.appendChild(btn);
  }
}

/** Format the display string; update the trigger label */
function _dtUpdateDisplay(state) {
  if (state.day === null) {
    state._display.textContent = "dd/mm/yyyy, --:--";
  } else {
    const dd = String(state.day).padStart(2, "0");
    const mm = String(state.month + 1).padStart(2, "0");
    const yyyy = state.year;
    const hhStr = state.hh !== null ? String(state.hh).padStart(2, "0") : "--";
    const mmStr = state.mm !== null ? String(state.mm).padStart(2, "0") : "--";
    state._display.textContent = `${dd}/${mm}/${yyyy}, ${hhStr}:${mmStr}`;
  }
}

/** Build an ISO datetime string from picker state, or "" if incomplete */
function _dtToISO(state) {
  if (state.day === null) return "";
  const pad = (n) => String(n).padStart(2, "0");
  const base = `${state.year}-${pad(state.month + 1)}-${pad(state.day)}`;
  if (state.hh !== null && state.mm !== null) return base + `T${pad(state.hh)}:${pad(state.mm)}`;
  return base + "T00:00";   // default to midnight when only date is picked
}

/** Reset a picker to blank state */
function _dtReset(state) {
  const now = new Date();
  state.year = now.getFullYear(); state.month = now.getMonth();
  state.day = state.hh = state.mm = null;
  state._hhInput.value = ""; state._mmInput.value = "";
  _dtUpdateDisplay(state);
}

// -- Audit data fetch & render ---------------------------------------------

async function fetchAuditLogs() {
  const params = new URLSearchParams();

  // emails – repeated param for each selected user
  _msGetSelected().forEach((email) => params.append("emails", email));

  const since = _dtSince ? _dtToISO(_dtSince) : "";
  const until = _dtUntil ? _dtToISO(_dtUntil) : "";
  if (since) params.set("since", since);
  if (until) params.set("until", until);

  try {
    const qs   = params.toString();
    const data = await apiCall("GET", "/admin/audit-logs" + (qs ? "?" + qs : ""));
    _auditLogs = data.logs || [];
    renderAuditTable(_auditLogs);
  } catch (err) {
    showToast("Failed to load audit logs: " + err.message, "error");
  }
}

// Module-level sort state for audit table
let _auditSortColumn = "created_at";
let _auditSortAsc = false;  // default: newest first

function renderAuditTable(logs) {
  const tbody = document.getElementById("audit-tbody");
  tbody.innerHTML = "";

  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No records found</td></tr>';
    return;
  }

  // Sort logs based on current sort state
  const sortedLogs = [...logs].sort((a, b) => {
    let valA, valB;

    if (_auditSortColumn === "id") {
      valA = a.id;
      valB = b.id;
    } else if (_auditSortColumn === "created_at") {
      valA = new Date(a.created_at).getTime();
      valB = new Date(b.created_at).getTime();
    } else if (_auditSortColumn === "user") {
      valA = (a.admin_email || a.target_email || "").toLowerCase();
      valB = (b.admin_email || b.target_email || "").toLowerCase();
    } else if (_auditSortColumn === "action") {
      valA = a.action.toLowerCase();
      valB = b.action.toLowerCase();
    } else if (_auditSortColumn === "request_ip") {
      valA = (a.request_ip || "").toLowerCase();
      valB = (b.request_ip || "").toLowerCase();
    }

    if (valA < valB) return _auditSortAsc ? -1 : 1;
    if (valA > valB) return _auditSortAsc ? 1 : -1;
    return 0;
  });

  sortedLogs.forEach((log) => {
    const userEmail = log.admin_email || log.target_email || '—';

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${log.id}</td>
      <td>${log.created_at ? new Date(log.created_at).toLocaleString() : '—'}</td>
      <td>${userEmail ? escapeHtml(userEmail) : '—'}</td>
      <td><span class="badge badge-${log.action === "user_login" ? "active" : "admin"}">${escapeHtml(log.action)}</span></td>
      <td>${log.request_ip ? escapeHtml(log.request_ip) : '—'}</td>
      <td>${log.detail ? escapeHtml(log.detail) : '—'}</td>
    `;
    tbody.appendChild(tr);
  });

  // Update sort indicators
  document.querySelectorAll(".sortable").forEach((th) => {
    const indicator = th.querySelector(".sort-indicator");
    if (th.dataset.column === _auditSortColumn) {
      indicator.textContent = _auditSortAsc ? " ▲" : " ▼";
    } else {
      indicator.textContent = "";
    }
  });
}

function clearAuditFilters() {
  // Uncheck all user checkboxes + select-all
  document.querySelectorAll(".ms-item input[type='checkbox']").forEach((cb) => { cb.checked = false; });
  document.getElementById("af-ms-all").checked = false;
  _msUpdateLabel();
  // Clear date pickers
  if (_dtSince) _dtReset(_dtSince);
  if (_dtUntil) _dtReset(_dtUntil);
  fetchAuditLogs();
}

async function exportAuditLogs() {
  try {
    const response = await fetch(BASE_URL + "/admin/audit-logs/export", {
      method: "GET",
      headers: { "Authorization": `Bearer ${getToken()}` },
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Export failed");
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-logs-${new Date().toISOString().split('T')[0]}.xlsx`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    showToast("Audit logs exported successfully");
  } catch (err) {
    showToast("Export failed: " + err.message, "error");
  }
}

// ==========================================================================
// 7.  Password generator – local (JS) fallback
// ==========================================================================

/**
 * Wordlists for memorable mode (mirrors the backend lists).
 */
const _ADJ  = [
  "bright","calm","dark","eager","fair","gentle","happy","keen","lively","magic",
  "noble","open","proud","quick","rich","swift","tall","ultra","vivid","warm",
  "young","azure","brave","clear","deep","fresh","grand","jolly","kind","lucky",
  "merry","neat","plain","quiet","royal","smart","tidy","upper","vital","wild",
  "bold","cool","damp","easy","fine","glad","huge","idle","just","lean",
];

const _NOUN = [
  "apple","bear","cedar","dawn","eagle","frost","grape","hawk","iris","jade",
  "kite","lake","maple","night","ocean","peach","quail","river","stone","tiger",
  "ultra","vine","wave","xenon","yak","zebra","amber","brook","crane","dove",
  "elm","flare","gold","holly","ivy","jewel","knot","lily","moss","oak",
  "pearl","rose","sage","thorn","umber","willow","yard","zeal","arch","birch",
];

const _SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";

/**
 * Cryptographically secure random choice from a string using
 * crypto.getRandomValues (Web Crypto API).
 */
function cryptoChoice(str) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return str[arr[0] % str.length];
}

/**
 * Generate a password entirely in the browser.
 *
 * mode    – "random" | "memorable" | "pin"
 * length  – target length (ignored for memorable)
 * options – { digits: bool, symbols: bool }  (only for random)
 */
function generatePasswordLocally(mode, length = 16, options = {}) {
  switch (mode) {
    case "memorable": {
      const adj  = _ADJ[crypto.getRandomValues(new Uint32Array(1))[0] % _ADJ.length];
      const noun = _NOUN[crypto.getRandomValues(new Uint32Array(1))[0] % _NOUN.length];
      const num  = 10 + (crypto.getRandomValues(new Uint32Array(1))[0] % 90);
      return `${adj}-${noun}-${num}`;
    }
    case "pin": {
      length = Math.max(4, Math.min(256, length || 6));
      let pin = "";
      for (let i = 0; i < length; i++) pin += cryptoChoice("0123456789");
      return pin;
    }
    case "random":
    default: {
      length = Math.max(6, Math.min(256, length || 16));
      const upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const lower  = "abcdefghijklmnopqrstuvwxyz";
      let charset  = upper + lower;
      if (options.digits)  charset += "0123456789";
      if (options.symbols) charset += _SYMBOLS;

      // Guarantee one upper and one lower
      const chars = [cryptoChoice(upper), cryptoChoice(lower)];
      for (let i = 2; i < length; i++) chars.push(cryptoChoice(charset));

      // Fisher-Yates shuffle using crypto
      for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
      }

      return chars.join("");
    }
  }
}

// ==========================================================================
// Shared utilities
// ==========================================================================

/** Logout – clear token and go to login. */
function logout() {
  clearToken();
  window.location.href = "login.html";
}

/** Escape HTML special characters to prevent XSS when rendering user data. */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ==========================================================================
// 7.  Password Generator Page
// ==========================================================================

async function initPasgenPage() {
  // Guard: redirect to login if no token
  if (!getToken()) {
    window.location.href = "login.html";
    return;
  }

  // Load user info and show admin nav if admin
  try {
    const user = await apiCall("GET", "/auth/me");
    document.getElementById("user-email").textContent = user.email;
    if (user.role === "admin") {
      document.getElementById("admin-nav-dropdown").style.display = "block";
    }
  } catch {
    window.location.href = "login.html";
    return;
  }

  // Type selector
  const typeBtns = document.querySelectorAll(".pasgen-type-btn");
  typeBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      typeBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      updatePasgenOptions();
      generatePasgenPassword();
    });
  });

  // Sync sliders with number inputs
  const lengthSlider = document.getElementById("pasgen-length");
  const lengthInput = document.getElementById("pasgen-length-input");
  const pinLengthSlider = document.getElementById("pasgen-pin-length");
  const pinLengthInput = document.getElementById("pasgen-pin-length-input");

  lengthSlider.addEventListener("input", (e) => {
    lengthInput.value = e.target.value;
    generatePasgenPassword();
  });

  lengthInput.addEventListener("input", (e) => {
    let val = parseInt(e.target.value) || 6;
    if (val < 6) val = 6;
    if (val > 256) val = 256;
    lengthInput.value = val;
    lengthSlider.value = val;
    generatePasgenPassword();
  });

  pinLengthSlider.addEventListener("input", (e) => {
    pinLengthInput.value = e.target.value;
    generatePasgenPassword();
  });

  pinLengthInput.addEventListener("input", (e) => {
    let val = parseInt(e.target.value) || 4;
    if (val < 4) val = 4;
    if (val > 12) val = 12;
    pinLengthInput.value = val;
    pinLengthSlider.value = val;
    generatePasgenPassword();
  });

  // Toggle checkboxes
  document.getElementById("pasgen-numbers").addEventListener("change", generatePasgenPassword);
  document.getElementById("pasgen-symbols").addEventListener("change", generatePasgenPassword);

  // Copy button
  document.getElementById("pasgen-copy-btn").addEventListener("click", async () => {
    const password = document.getElementById("pasgen-display").textContent;
    if (!password) {
      showToast("No password to copy", "error");
      return;
    }
    try {
      await navigator.clipboard.writeText(password);
      showToast("Password copied to clipboard", "success");
    } catch {
      showToast("Failed to copy to clipboard", "error");
    }
  });

  // Refresh button
  document.getElementById("pasgen-refresh-btn").addEventListener("click", generatePasgenPassword);

  // Generate initial password
  generatePasgenPassword();
}

function updatePasgenOptions() {
  const mode = document.querySelector(".pasgen-type-btn.active").dataset.mode;

  document.getElementById("pasgen-random-options").style.display = (mode === "random") ? "block" : "none";
  document.getElementById("pasgen-memorable-options").style.display = (mode === "memorable") ? "block" : "none";
  document.getElementById("pasgen-pin-options").style.display = (mode === "pin") ? "block" : "none";
}

async function generatePasgenPassword() {
  const mode = document.querySelector(".pasgen-type-btn.active").dataset.mode;
  let length, includeDigits, includeSymbols;

  if (mode === "random") {
    length = parseInt(document.getElementById("pasgen-length-input").value, 10) || 20;
    includeDigits = document.getElementById("pasgen-numbers").checked;
    includeSymbols = document.getElementById("pasgen-symbols").checked;
  } else if (mode === "pin") {
    length = parseInt(document.getElementById("pasgen-pin-length-input").value, 10) || 6;
  } else {
    length = 16; // Memorable doesn't use length param
  }

  try {
    const params = new URLSearchParams({ mode, length });
    if (mode === "random") {
      params.set("include_digits", includeDigits);
      params.set("include_symbols", includeSymbols);
    }

    const data = await apiCall("GET", `/vault/generate-password?${params}`);
    document.getElementById("pasgen-display").textContent = data.password;
  } catch {
    // Fallback: generate locally
    const pw = generatePasswordLocally(mode, length, {
      digits: mode === "random" ? includeDigits : false,
      symbols: mode === "random" ? includeSymbols : false,
    });
    document.getElementById("pasgen-display").textContent = pw;
  }
}
