// Shared helpers for every dashboard page. Loaded via <script src="/assets/app.js">.
window.PL = (function () {
  const ICONS = {
    home: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/></svg>',
    brand: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></svg>',
    tx: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 109-9 9 9 0 00-9 9z"/><path d="M12 7v5l4 2"/></svg>',
    download: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>',
    docs: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3v5a2 2 0 002 2h5"/><path d="M17 21H7a2 2 0 01-2-2V5a2 2 0 012-2h7l5 5v11a2 2 0 01-2 2z"/></svg>',
    settings: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06A1.65 1.65 0 005 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06A1.65 1.65 0 009 4.6a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09A1.65 1.65 0 0015 4.6a1.65 1.65 0 001.82.33l.06-.06a2 2 0 112.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>',
    donate: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.8 4.6a5.5 5.5 0 00-7.8 0L12 5.6l-1-1a5.5 5.5 0 00-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 000-7.8z"/></svg>',
    admin: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.7-7 9-4-1.3-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    logout: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>',
    copy: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 01-1-1V4a1 1 0 011-1h10a1 1 0 011 1v1"/></svg>',
    good: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>',
    bad: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>',
    menu: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>',
    chevron: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
  };

  const NAV_ITEMS = [
    { id: "dashboard", href: "/app/dashboard.html", label: "Dashboard", icon: "home" },
    { id: "brand", href: "/app/brand.html", label: "Brands", icon: "brand" },
    { id: "transactions", href: "/app/transactions.html", label: "Transactions", icon: "tx" },
    { id: "download", href: "/app/download.html", label: "Download", icon: "download" },
    { id: "docs", href: "/app/docs.html", label: "Docs", icon: "docs" },
    { id: "settings", href: "/app/settings.html", label: "Settings", icon: "settings" },
    { id: "donate", href: "/app/donate.html", label: "Donate", icon: "donate" },
  ];

  function fmt(n) {
    return Number(n || 0).toLocaleString("en-BD", { maximumFractionDigits: 2 });
  }
  function fmtDate(ms) {
    const d = new Date(ms);
    return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) + ", " +
      d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  }

  // Escapes any user-controlled string before it's inserted into innerHTML
  // (brand names, user names/emails, invoice references, TrxIDs, raw SMS
  // text, admin audit-log details...). Every page that renders such values
  // MUST run them through this first — it's the single most important line
  // of defense against stored XSS in this app.
  function esc(value) {
    return String(value === null || value === undefined ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  async function api(path, opts) {
    opts = opts || {};
    const res = await fetch("/api" + path, {
      method: opts.method || "GET",
      headers: opts.body ? { "Content-Type": "application/json" } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: "include",
    });
    let data = {};
    try { data = await res.json(); } catch {}
    return { ok: res.ok, status: res.status, data };
  }

  function ensureToastHost() {
    let host = document.getElementById("toastHost");
    if (!host) {
      host = document.createElement("div");
      host.id = "toastHost";
      document.body.appendChild(host);
    }
    return host;
  }

  function toast(message, kind) {
    const host = ensureToastHost();
    const el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.innerHTML = (kind === "good" ? ICONS.good : kind === "bad" ? ICONS.bad : "") + "<div>" + esc(message) + "</div>";
    host.appendChild(el);
    setTimeout(() => { el.style.opacity = "0"; el.style.transition = "opacity .3s"; setTimeout(() => el.remove(), 300); }, 3600);
  }

  // ---- nav: everything lives inside one "Menu" dropdown button ----------

  function renderNav(active, user) {
    const initial = ((user && (user.name || user.email)) || "U").trim().charAt(0).toUpperCase();
    const links = NAV_ITEMS.map(
      (n) => `<a href="${n.href}" class="${n.id === active ? "active" : ""}">${ICONS[n.icon]}<span>${n.label}</span></a>`
    ).join("");
    const adminLink = user && user.isAdmin
      ? `<a href="/app/admin/index.html" class="${active === "admin" ? "active" : ""}">${ICONS.admin}<span>Admin</span></a>`
      : "";

    return `
      <div class="sidebarOverlay" id="plSidebarOverlay"></div>
      <div class="sidebar-topbar" id="plTopbar">
        <button class="sidebarToggleBtn" id="plSidebarToggle" aria-label="Menu">${ICONS.menu}</button>
        <a href="/app/dashboard.html" class="brand-logo"><img src="/assets/logos/freepay.svg" alt="FreePay">FreePay</a>
      </div>
      <aside class="sidebar" id="plSidebar">
        <a href="/app/dashboard.html" class="brand-logo sidebar-brand"><img src="/assets/logos/freepay.svg" alt="FreePay">FreePay</a>
        <nav class="sidebar-nav">${links}${adminLink}</nav>
        <div class="sidebar-user">
          <div class="navavatar" title="${esc(user ? user.email : "")}">${esc(initial)}</div>
          <div class="sidebar-user-info">
            <div class="name">${esc((user && (user.name || user.email.split("@")[0])) || "")}</div>
            <div class="email">${esc(user ? user.email : "")}</div>
          </div>
          <button class="iconbtn" id="plLogoutBtn" title="Logout">${ICONS.logout}</button>
        </div>
      </aside>`;
  }

  function mountNav(active, user) {
    const slot = document.getElementById("navSlot");
    if (slot) slot.outerHTML = renderNav(active, user);

    const btn = document.getElementById("plLogoutBtn");
    if (btn) btn.addEventListener("click", async () => {
      await api("/auth/logout", { method: "POST" });
      location.href = "/app/login.html";
    });

    const sidebar = document.getElementById("plSidebar");
    const toggleBtn = document.getElementById("plSidebarToggle");
    const overlay = document.getElementById("plSidebarOverlay");
    if (sidebar && toggleBtn && overlay) {
      const closeSidebar = () => { sidebar.classList.remove("open"); overlay.classList.remove("open"); };
      toggleBtn.addEventListener("click", () => {
        sidebar.classList.toggle("open");
        overlay.classList.toggle("open");
      });
      overlay.addEventListener("click", closeSidebar);
      document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSidebar(); });
      sidebar.querySelectorAll("a").forEach((a) => a.addEventListener("click", closeSidebar));
    }
  }

  // Call at the top of every protected page. Redirects to login if not
  // authenticated, otherwise mounts the nav bar and resolves with the user.
  async function requireAuth(active) {
    const r = await api("/me");
    if (!r.ok) {
      location.href = "/app/login.html";
      return null;
    }
    mountNav(active, r.data.user);
    return r.data.user;
  }

  async function requireAdmin(active) {
    const user = await requireAuth(active);
    if (!user) return null;
    if (!user.isAdmin) {
      toast("এই পেজটি শুধু Admin-দের জন্য।", "bad");
      setTimeout(() => (location.href = "/app/dashboard.html"), 1200);
      return null;
    }
    return user;
  }

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.innerHTML;
      btn.textContent = "Copied!";
      btn.classList.add("copied");
      setTimeout(() => { btn.innerHTML = orig; btn.classList.remove("copied"); }, 1300);
    });
  }

  // Adds a floating "Copy" button to the top-right corner of every <pre>
  // inside `container` (or the whole document if omitted). Used by docs.html
  // so every code example can be copied with one click.
  function attachCopyButtons(container) {
    const root = container || document;
    root.querySelectorAll("pre").forEach((pre) => {
      if (pre.dataset.copyReady) return;
      pre.dataset.copyReady = "1";
      pre.style.position = "relative";
      const btn = document.createElement("button");
      btn.className = "codeCopyBtn";
      btn.type = "button";
      btn.innerHTML = ICONS.copy + "<span>Copy</span>";
      btn.addEventListener("click", () => copyText(pre.innerText, btn));
      pre.appendChild(btn);
    });
  }

  return {
    ICONS, fmt, fmtDate, esc, api, toast, renderNav, mountNav,
    requireAuth, requireAdmin, copyText, attachCopyButtons,
  };
})();
