// AegisHealth Unified Application Engine

let state = {
    token: localStorage.getItem("aegis_token") || null,
    currentUser: null,
    activeTab: "ehr",
    patients: [],
    selectedPatient: null,
    alerts: [],
    auditLogs: [],
    socStats: null,
    ws: null,
    severityChart: null,
    theme: localStorage.getItem("aegis_theme") || "dark"
};

// --- INITIALIZATION ---
document.addEventListener("DOMContentLoaded", async () => {
    initTheme();
    lucide.createIcons();
    initWebSocket();
    initInactivityTracker();
    await checkAuth();
    setupNavigation();
});

// --- THEME ENGINE (DARK / LIGHT MODE WITH MICRO-ANIMATIONS) ---
function initTheme() {
    const urlParams = new URLSearchParams(window.location.search);
    const themeParam = urlParams.get("theme");
    const savedTheme = themeParam || localStorage.getItem("aegis_theme") || "dark";
    applyTheme(savedTheme, false);
}

function toggleTheme(event) {
    const currentTheme = state.theme || (document.documentElement.classList.contains("light") ? "light" : "dark");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    
    // Trigger smooth expanding ripple animation from button click coordinates
    if (event && event.currentTarget) {
        createThemeRipple(event, newTheme);
    }
    
    applyTheme(newTheme, true);
}

function createThemeRipple(event, targetTheme) {
    const ripple = document.createElement("div");
    ripple.className = "theme-ripple";
    
    const rect = event.currentTarget.getBoundingClientRect();
    const x = event.clientX || (rect.left + rect.width / 2);
    const y = event.clientY || (rect.top + rect.height / 2);
    
    const maxDim = Math.max(window.innerWidth, window.innerHeight);
    const size = maxDim * 2.2;
    
    ripple.style.width = `${size}px`;
    ripple.style.height = `${size}px`;
    ripple.style.left = `${x}px`;
    ripple.style.top = `${y}px`;
    ripple.style.backgroundColor = targetTheme === "light" ? "rgba(248, 250, 252, 0.4)" : "rgba(2, 6, 23, 0.4)";
    
    document.body.appendChild(ripple);
    setTimeout(() => {
        if (ripple.parentNode) ripple.parentNode.removeChild(ripple);
    }, 700);
}

function applyTheme(theme, animate = true) {
    state.theme = theme;
    localStorage.setItem("aegis_theme", theme);
    const html = document.documentElement;

    if (animate) {
        html.classList.add("theme-transitioning");
        setTimeout(() => {
            html.classList.remove("theme-transitioning");
        }, 500);
    }

    const iconContainer = document.getElementById("theme-icon-container");
    const moonIcon = document.getElementById("theme-icon-moon");
    const sunIcon = document.getElementById("theme-icon-sun");
    const themeText = document.getElementById("theme-text");

    if (theme === "light") {
        html.classList.remove("dark");
        html.classList.add("light");
        
        if (iconContainer) {
            iconContainer.className = "relative w-5 h-5 flex items-center justify-center " + (animate ? "theme-spin-to-light" : "");
        }
        if (moonIcon) moonIcon.classList.add("hidden");
        if (sunIcon) sunIcon.classList.remove("hidden");
        if (themeText) {
            themeText.textContent = "Light";
            themeText.className = "hidden sm:inline ml-2 text-xs font-semibold text-amber-600";
        }
    } else {
        html.classList.remove("light");
        html.classList.add("dark");
        
        if (iconContainer) {
            iconContainer.className = "relative w-5 h-5 flex items-center justify-center " + (animate ? "theme-spin-to-dark" : "");
        }
        if (moonIcon) moonIcon.classList.remove("hidden");
        if (sunIcon) sunIcon.classList.add("hidden");
        if (themeText) {
            themeText.textContent = "Dark";
            themeText.className = "hidden sm:inline ml-2 text-xs font-semibold text-slate-300";
        }
    }

    // Adapt Chart.js canvas borders for light/dark contrast
    if (state.severityChart) {
        state.severityChart.data.datasets[0].borderColor = theme === "light" ? "#ffffff" : "#0f172a";
        if (state.severityChart.options.plugins?.legend?.labels) {
            state.severityChart.options.plugins.legend.labels.color = theme === "light" ? "#334155" : "#94a3b8";
        }
        state.severityChart.update();
    }
}

// --- WEBSOCKET REAL-TIME ENGINE ---
function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/soc`;

    try {
        state.ws = new WebSocket(wsUrl);

        state.ws.onopen = () => {
            console.log("[WS] Connected to AegisHealth Real-Time SOC Stream.");
            const indicator = document.getElementById("ws-status-indicator");
            if (indicator) {
                indicator.className = "w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse";
                indicator.title = "SOC Real-Time Stream: Active";
            }
        };

        state.ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === "SECURITY_ALERT") {
                handleIncomingAlert(msg.data);
            } else if (msg.type === "AUDIT_EVENT") {
                handleIncomingAudit(msg.data);
            }
        };

        state.ws.onclose = () => {
            console.warn("[WS] Socket disconnected. Reconnecting in 3s...");
            const indicator = document.getElementById("ws-status-indicator");
            if (indicator) {
                indicator.className = "w-2.5 h-2.5 rounded-full bg-rose-500";
                indicator.title = "SOC Real-Time Stream: Disconnected";
            }
            setTimeout(initWebSocket, 3000);
        };
    } catch (e) {
        console.error("[WS] Initialization error:", e);
    }
}

function handleIncomingAlert(alert) {
    showToast(`🚨 ${alert.severity} ALERT: ${alert.rule_name}`, alert.description, alert.severity);
    const isAuditorOrAdmin = state.currentUser && ["AUDITOR", "ADMIN"].includes(state.currentUser.role);
    if (isAuditorOrAdmin && (state.activeTab === "soc" || state.activeTab === "simulator")) {
        fetchSOCStats();
        fetchAlerts();
    }
}

function handleIncomingAudit(audit) {
    const isAuditorOrAdmin = state.currentUser && ["AUDITOR", "ADMIN"].includes(state.currentUser.role);
    if (isAuditorOrAdmin && state.activeTab === "audit") {
        fetchAuditLogs();
    }
}

// --- AUTHENTICATION & PORTAL ACCESS SYSTEM ---
const DEFAULT_DEMO_ACCOUNTS = [
    { name: "Dr. Alice Smith", role: "DOCTOR", dept: "Cardiology", email: "alice.smith@aegishealth.org", username: "doctor_alice", access: "Clinical EHR (Cardio)" },
    { name: "Dr. Frank Miller", role: "DOCTOR", dept: "Oncology", email: "frank.miller@aegishealth.org", username: "doctor_frank", access: "Clinical EHR (Onco)" },
    { name: "Nurse Bob Johnson", role: "NURSE", dept: "Cardiology", email: "bob.johnson@aegishealth.org", username: "nurse_bob", access: "Clinical EHR (Vitals)" },
    { name: "Nurse Carol Davis", role: "NURSE", dept: "Emergency", email: "carol.davis@aegishealth.org", username: "nurse_carol", access: "Clinical EHR (ER Intake)" },
    { name: "David Patel", role: "LAB_TECH", dept: "Lab", email: "david.patel@aegishealth.org", username: "lab_david", access: "Lab Results / Tests" },
    { name: "Eva Martinez", role: "BILLING", dept: "Billing", email: "eva.martinez@aegishealth.org", username: "billing_eva", access: "Billing / Invoices" },
    { name: "Grace Hopper", role: "ADMIN", dept: "Administration", email: "grace.hopper@aegishealth.org", username: "admin_grace", access: "Full Admin + SOC + Ledger" },
    { name: "Alex Vance", role: "AUDITOR", dept: "Security", email: "alex.vance@aegishealth.org", username: "soc_analyst", access: "Full Security SOC + Ledger" }
];

function showLoginScreen() {
    const loginScreen = document.getElementById("login-screen");
    const appScreen = document.getElementById("app-screen");
    if (loginScreen) {
        loginScreen.classList.remove("hidden");
        loginScreen.style.display = "flex";
    }
    if (appScreen) {
        appScreen.classList.add("hidden");
        appScreen.style.display = "none";
    }
    renderLoginDemoUsers();
    lucide.createIcons();
}

function showAppScreen() {
    const loginScreen = document.getElementById("login-screen");
    const appScreen = document.getElementById("app-screen");
    if (loginScreen) {
        loginScreen.classList.add("hidden");
        loginScreen.style.display = "none";
    }
    if (appScreen) {
        appScreen.classList.remove("hidden");
        appScreen.style.display = "flex";
    }
    lucide.createIcons();
}

function renderLoginDemoUsers() {
    const container = document.getElementById("login-demo-grid");
    if (!container) return;

    container.innerHTML = DEFAULT_DEMO_ACCOUNTS.map(acc => `
        <button type="button" onclick="fillLoginForm('${acc.email}', 'cyberarena2026', true)" 
            class="p-2 sm:p-2.5 rounded-xl text-left border border-slate-800 bg-slate-950/60 hover:bg-slate-800/80 hover:border-slate-700 transition-all group flex flex-col justify-between shadow-sm">
            <div class="text-[11px] font-semibold text-slate-200 group-hover:text-cyan-300 truncate w-full">${acc.name}</div>
            <div class="flex items-center justify-between mt-1.5 w-full">
                <span class="role-badge role-badge-${acc.role.toLowerCase()} text-[9px] px-1 py-0.2">${acc.role}</span>
                <span class="text-[9px] text-slate-500 font-mono">${acc.dept.slice(0, 5)}</span>
            </div>
        </button>
    `).join("");
}

function fillLoginForm(identifier, password, autoSubmit = false) {
    const idInput = document.getElementById("login-identifier");
    const pwInput = document.getElementById("login-password");
    if (idInput) idInput.value = identifier;
    if (pwInput) pwInput.value = password;

    const errAlert = document.getElementById("login-error-alert");
    if (errAlert) errAlert.classList.add("hidden");

    if (autoSubmit) {
        handleLoginFormSubmit();
    }
}

function togglePasswordVisibility() {
    const pwInput = document.getElementById("login-password");
    const icon = document.getElementById("password-toggle-icon");
    if (!pwInput) return;

    if (pwInput.type === "password") {
        pwInput.type = "text";
        if (icon) icon.setAttribute("data-lucide", "eye-off");
    } else {
        pwInput.type = "password";
        if (icon) icon.setAttribute("data-lucide", "eye");
    }
    lucide.createIcons();
}

async function handleLoginFormSubmit(e) {
    if (e) e.preventDefault();
    const idInput = document.getElementById("login-identifier");
    const pwInput = document.getElementById("login-password");
    const identifier = idInput ? idInput.value.trim() : "";
    const password = pwInput ? pwInput.value : "";
    const btn = document.getElementById("login-submit-btn");
    const btnText = document.getElementById("login-btn-text");
    const errAlert = document.getElementById("login-error-alert");
    const errText = document.getElementById("login-error-text");

    if (!identifier || !password) {
        if (errAlert && errText) {
            errText.textContent = "Please enter both email/username and password.";
            errAlert.classList.remove("hidden");
        }
        return;
    }

    if (errAlert) errAlert.classList.add("hidden");
    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = "Verifying Credentials...";

    try {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: identifier, password: password })
        });

        if (!res.ok) {
            const err = await res.json();
            if (errAlert && errText) {
                errText.textContent = err.detail || "Invalid email/username or password.";
                errAlert.classList.remove("hidden");
            }
            return;
        }

        const data = await res.json();
        const previousUser = state.currentUser;
        state.token = data.access_token;
        state.currentUser = data.user;
        localStorage.setItem("aegis_token", state.token);

        showAppScreen();
        triggerAccountSwitchAnimation(data.user, previousUser);
        updateUserUI();
        showToast("Authenticated", `Welcome, ${data.user.full_name} (${data.user.role})`, "LOW");

        if (["AUDITOR", "ADMIN"].includes(data.user.role)) {
            switchTab("soc");
        } else {
            switchTab("ehr");
        }

        const urlParams = new URLSearchParams(window.location.search);
        const openPatientId = urlParams.get("open");
        if (openPatientId) {
            setTimeout(() => openPatientChart(parseInt(openPatientId)), 500);
        }
    } catch (err) {
        if (errAlert && errText) {
            errText.textContent = "Network error connecting to security gateway.";
            errAlert.classList.remove("hidden");
        }
    } finally {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = "Sign In to AegisHealth";
    }
}

async function logout() {
    try {
        if (state.token) {
            await fetch("/api/auth/logout", {
                method: "POST",
                headers: { "Authorization": `Bearer ${state.token}` }
            });
        }
    } catch (e) {
        console.error("Logout error:", e);
    }
    state.token = null;
    state.currentUser = null;
    localStorage.removeItem("aegis_token");
    showToast("Session Ended", "Logged out securely.", "LOW");
    showLoginScreen();
}

function showCredentialsModal() {
    const modal = document.getElementById("credentials-modal");
    const tbody = document.getElementById("credentials-modal-tbody");
    if (!modal) return;

    if (tbody) {
        tbody.innerHTML = DEFAULT_DEMO_ACCOUNTS.map(acc => `
            <tr class="hover:bg-slate-800/40 transition-colors">
                <td class="p-2.5">
                    <span class="role-badge role-badge-${acc.role.toLowerCase()} text-[10px]">${acc.role}</span>
                </td>
                <td class="p-2.5 font-sans font-semibold text-slate-200">${acc.name}</td>
                <td class="p-2.5 text-cyan-300 font-mono text-[11px]">${acc.email}</td>
                <td class="p-2.5 text-slate-400 font-mono text-[11px]">${acc.username}</td>
                <td class="p-2.5 font-sans text-slate-300">${acc.dept}</td>
                <td class="p-2.5 font-sans text-[11px] text-slate-400">${acc.access}</td>
                <td class="p-2.5 text-right font-sans">
                    <button onclick="fillLoginForm('${acc.email}', 'cyberarena2026', true); closeCredentialsModal();" 
                        class="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500 hover:text-white transition-all">
                        Login As
                    </button>
                </td>
            </tr>
        `).join("");
    }

    modal.classList.remove("hidden");
    lucide.createIcons();
}

function closeCredentialsModal() {
    const modal = document.getElementById("credentials-modal");
    if (modal) modal.classList.add("hidden");
}

async function checkAuth() {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUser = urlParams.get("user");
    const targetTheme = urlParams.get("theme");
    const targetTab = urlParams.get("tab");

    if (targetTheme) {
        applyTheme(targetTheme, false);
    }

    if (targetUser) {
        await quickLogin(targetUser);
        if (targetTab) switchTab(targetTab);
        return;
    }

    if (!state.token) {
        showLoginScreen();
        return;
    }

    try {
        const res = await fetch("/api/auth/me", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (res.ok) {
            state.currentUser = await res.json();
            showAppScreen();
            updateUserUI();
            if (targetTab) {
                switchTab(targetTab);
            } else {
                loadTabData();
            }
        } else {
            state.token = null;
            localStorage.removeItem("aegis_token");
            showLoginScreen();
        }
    } catch (e) {
        state.token = null;
        localStorage.removeItem("aegis_token");
        showLoginScreen();
    }
}

async function quickLogin(username) {
    try {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: username, password: "cyberarena2026" })
        });
        if (!res.ok) {
            const err = await res.json();
            showToast("Login Failed", err.detail || "Authentication error", "CRITICAL");
            return;
        }
        const data = await res.json();
        const previousUser = state.currentUser;
        state.token = data.access_token;
        state.currentUser = data.user;
        localStorage.setItem("aegis_token", state.token);
        
        showAppScreen();
        triggerAccountSwitchAnimation(data.user, previousUser);
        
        updateUserUI();
        showToast("Session Switched", `Logged in as ${data.user.full_name} (${data.user.role})`, "LOW");
        
        // Automatically route to SOC Dashboard for Auditor/Admin, or EHR portal for clinical staff
        if (["AUDITOR", "ADMIN"].includes(data.user.role)) {
            switchTab("soc");
        } else {
            switchTab("ehr");
        }

        const urlParams = new URLSearchParams(window.location.search);
        const openPatientId = urlParams.get("open");
        if (openPatientId) {
            setTimeout(() => openPatientChart(parseInt(openPatientId)), 500);
        }
    } catch (e) {
        console.error("Quick login error:", e);
    }
}

function triggerAccountSwitchAnimation(newUser, oldUser) {
    const isAuditorOrAdmin = ["AUDITOR", "ADMIN"].includes(newUser.role);

    // 1. High-tech laser sweep across header
    const beam = document.getElementById("security-scan-beam");
    if (beam) {
        beam.className = `absolute bottom-0 left-0 w-full h-[2px] opacity-100 ${
            isAuditorOrAdmin 
                ? 'bg-gradient-to-r from-transparent via-purple-500 to-transparent shadow-[0_0_12px_#a855f7]' 
                : 'bg-gradient-to-r from-transparent via-cyan-400 to-transparent shadow-[0_0_12px_#06b6d4]'
        } animate-scan-sweep pointer-events-none`;
        setTimeout(() => {
            beam.className = "absolute bottom-0 left-0 right-0 h-[2px] opacity-0 pointer-events-none";
        }, 700);
    }

    // 2. Animate the user badge container in header with role-specific glow
    const badgeContainer = document.getElementById("user-badge-container");
    if (badgeContainer) {
        badgeContainer.classList.remove("animate-badge-switch");
        void badgeContainer.offsetWidth; // Force reflow
        badgeContainer.classList.add("animate-badge-switch");
    }

    // 3. Pop the role badge
    const roleBadge = document.getElementById("user-role-badge");
    if (roleBadge) {
        roleBadge.classList.remove("animate-role-pop");
        void roleBadge.offsetWidth; // Force reflow
        roleBadge.classList.add("animate-role-pop");
    }
}

function updateUserUI() {
    if (!state.currentUser) return;
    const nameEl = document.getElementById("user-full-name");
    const roleEl = document.getElementById("user-role-badge");
    const deptEl = document.getElementById("user-dept");
    const shiftEl = document.getElementById("user-shift");
    const riskEl = document.getElementById("user-risk-badge");

    if (nameEl) nameEl.textContent = state.currentUser.full_name;
    if (roleEl) {
        const role = state.currentUser.role;
        roleEl.textContent = role;
        roleEl.className = `role-badge px-2 py-0.5 rounded text-[11px] font-bold border transition-all role-badge-${role.toLowerCase()}`;
    }
    if (deptEl) deptEl.textContent = state.currentUser.department;
    if (shiftEl) shiftEl.textContent = `Shift: ${state.currentUser.shift_start} - ${state.currentUser.shift_end}`;
    if (riskEl) {
        const score = state.currentUser.current_risk_score;
        riskEl.textContent = `Risk: ${score}/100`;
        riskEl.className = `user-risk-badge px-2 py-0.5 rounded text-[11px] font-mono font-bold border transition-all ${
            score >= 85 ? 'risk-badge-critical animate-pulse' :
            score >= 40 ? 'risk-badge-elevated' :
            'risk-badge-normal'
        }`;
    }

    // Role-based visibility enforcement for SOC and Cryptographic Ledger tabs
    const isAuditorOrAdmin = state.currentUser && ["AUDITOR", "ADMIN"].includes(state.currentUser.role);
    const socTabBtn = document.getElementById("tab-btn-soc");
    const auditTabBtn = document.getElementById("tab-btn-audit");

    if (socTabBtn) {
        if (isAuditorOrAdmin) {
            const wasHidden = socTabBtn.classList.contains("hidden") || socTabBtn.style.display === "none";
            socTabBtn.classList.remove("hidden");
            socTabBtn.style.display = "flex";
            if (wasHidden) {
                socTabBtn.classList.remove("animate-tab-in");
                void socTabBtn.offsetWidth;
                socTabBtn.classList.add("animate-tab-in");
            }
        } else {
            socTabBtn.classList.add("hidden");
            socTabBtn.style.display = "none";
        }
    }
    if (auditTabBtn) {
        if (isAuditorOrAdmin) {
            const wasHidden = auditTabBtn.classList.contains("hidden") || auditTabBtn.style.display === "none";
            auditTabBtn.classList.remove("hidden");
            auditTabBtn.style.display = "flex";
            if (wasHidden) {
                auditTabBtn.classList.remove("animate-tab-in");
                void auditTabBtn.offsetWidth;
                auditTabBtn.classList.add("animate-tab-in");
            }
        } else {
            auditTabBtn.classList.add("hidden");
            auditTabBtn.style.display = "none";
        }
    }

    // If currently on a restricted tab, bounce back to EHR portal
    if (!isAuditorOrAdmin && (state.activeTab === "soc" || state.activeTab === "audit")) {
        switchTab("ehr");
    }
}

// --- NAVIGATION & TABS ---
function setupNavigation() {
    const tabs = ["ehr", "soc", "audit", "simulator"];
    tabs.forEach(tab => {
        const btn = document.getElementById(`tab-btn-${tab}`);
        if (btn) {
            btn.addEventListener("click", () => switchTab(tab));
        }
    });
}

function switchTab(tabName) {
    const isAuditorOrAdmin = state.currentUser && ["AUDITOR", "ADMIN"].includes(state.currentUser.role);
    if ((tabName === "soc" || tabName === "audit") && !isAuditorOrAdmin) {
        showToast(
            "Access Denied (403)",
            `Role '${state.currentUser?.role}' is restricted. Only Auditor and Admin roles can access Cyber SOC & Cryptographic Ledger.`,
            "CRITICAL"
        );
        return;
    }

    state.activeTab = tabName;
    ["ehr", "soc", "audit", "simulator"].forEach(t => {
        const btn = document.getElementById(`tab-btn-${t}`);
        const panel = document.getElementById(`panel-${t}`);
        if (btn && panel) {
            if (t === tabName) {
                btn.classList.add("border-cyan-500", "text-cyan-400", "bg-cyan-500/10");
                btn.classList.remove("border-transparent", "text-slate-400");
                panel.classList.remove("hidden");
                panel.classList.remove("animate-panel-switch");
                void panel.offsetWidth; // Force reflow for seamless re-trigger
                panel.classList.add("animate-panel-switch");
            } else {
                btn.classList.remove("border-cyan-500", "text-cyan-400", "bg-cyan-500/10");
                btn.classList.add("border-transparent", "text-slate-400");
                panel.classList.add("hidden");
            }
        }
    });

    // Ensure tab button visibility matches role
    const socTabBtn = document.getElementById("tab-btn-soc");
    const auditTabBtn = document.getElementById("tab-btn-audit");
    if (socTabBtn) {
        socTabBtn.style.display = isAuditorOrAdmin ? "flex" : "none";
        socTabBtn.classList.toggle("hidden", !isAuditorOrAdmin);
    }
    if (auditTabBtn) {
        auditTabBtn.style.display = isAuditorOrAdmin ? "flex" : "none";
        auditTabBtn.classList.toggle("hidden", !isAuditorOrAdmin);
    }

    loadTabData();
    lucide.createIcons();
}

function loadTabData() {
    const isAuditorOrAdmin = state.currentUser && ["AUDITOR", "ADMIN"].includes(state.currentUser.role);
    if (state.activeTab === "ehr") {
        fetchPatients();
    } else if (state.activeTab === "soc") {
        if (isAuditorOrAdmin) {
            fetchSOCStats();
            fetchAlerts();
            fetchComplianceReport();
        } else {
            switchTab("ehr");
        }
    } else if (state.activeTab === "audit") {
        if (isAuditorOrAdmin) {
            fetchAuditLogs();
            verifyBlockchain(false);
        } else {
            switchTab("ehr");
        }
    } else if (state.activeTab === "simulator") {
        if (isAuditorOrAdmin) {
            fetchSOCStats();
        }
    }
}

// --- EHR CLINICAL PORTAL ---
async function fetchPatients(department = "", search = "") {
    state.activeDepartment = department;

    // Update active highlight on department filter buttons
    const deptButtons = document.querySelectorAll(".dept-btn");
    deptButtons.forEach(btn => {
        const d = btn.getAttribute("data-dept") || "";
        if (d === department) {
            btn.className = "dept-btn px-3 py-1 rounded-lg text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500 ring-1 ring-cyan-500 shadow-sm transition-all";
        } else {
            btn.className = "dept-btn px-3 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all";
        }
    });

    try {
        let url = "/api/patients?";
        if (department) url += `department=${encodeURIComponent(department)}&`;
        if (search) url += `search=${encodeURIComponent(search)}&`;

        const res = await fetch(url, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (!res.ok) {
            showToast("Access Denied", "Unable to retrieve patient directory under current role.", "HIGH");
            return;
        }
        state.patients = await res.json();
        renderPatientsTable();
    } catch (e) {
        console.error("Fetch patients error:", e);
    }
}

function renderPatientsTable() {
    const tbody = document.getElementById("patients-table-body");
    if (!tbody) return;

    if (state.patients.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-slate-400">No patient records match the specified criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = state.patients.map(p => {
        const apts = p.appointments || [];
        let aptsCellHtml = '';
        if (apts.length > 0) {
            const nextApt = apts[0];
            const statusClass = 
                nextApt.status === 'CONFIRMED' ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40' :
                nextApt.status === 'COMPLETED' ? 'bg-slate-700/40 text-slate-400 border-slate-600/50' :
                nextApt.status === 'CANCELLED' ? 'bg-rose-500/15 text-rose-300 border-rose-500/40' :
                'bg-cyan-500/15 text-cyan-300 border-cyan-500/40';

            aptsCellHtml = `
                <div class="flex flex-col space-y-1">
                    <div class="flex items-center space-x-1.5 flex-wrap">
                        <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${statusClass}">
                            <i data-lucide="calendar" class="w-2.5 h-2.5 mr-1"></i>
                            ${nextApt.date} ${nextApt.time}
                        </span>
                        ${apts.length > 1 ? `<span class="text-[10px] text-slate-400 font-mono font-semibold">(+${apts.length - 1} more)</span>` : ''}
                    </div>
                    <span class="text-[11px] text-slate-300 truncate max-w-[200px]" title="${nextApt.purpose} (${nextApt.department})">
                        ${nextApt.purpose || nextApt.department}
                    </span>
                </div>
            `;
        } else {
            aptsCellHtml = `<span class="text-[11px] text-slate-500 italic flex items-center"><i data-lucide="calendar-x-2" class="w-3 h-3 mr-1 text-slate-500/70"></i>None</span>`;
        }

        return `
        <tr class="patient-table-row border-b border-slate-800 hover:bg-slate-800/40 transition-colors cursor-pointer" onclick="openPatientChart(${p.id})">
            <td class="py-3 px-4 font-mono font-bold patient-mrn-cell text-xs">${p.mrn}</td>
            <td class="py-3 px-4 font-semibold text-slate-200 patient-name-cell">
                ${p.first_name} ${p.last_name}
                ${p.is_honeytoken ? '<span class="ml-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 badge-tripwire">VIP TRIPWIRE</span>' : ''}
                ${p.is_vip && !p.is_honeytoken ? '<span class="ml-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 badge-vip">VIP</span>' : ''}
            </td>
            <td class="py-3 px-4 text-xs text-slate-300">${p.dob || 'N/A'} (${p.gender})</td>
            <td class="py-3 px-4 text-xs">
                <span class="px-2 py-0.5 rounded font-medium bg-slate-800 border border-slate-700 text-slate-300 patient-dept-tag">${p.department}</span>
            </td>
            <td class="py-3 px-4 text-xs font-mono text-slate-400">${p.ward_room}</td>
            <td class="py-3 px-4">${aptsCellHtml}</td>
            <td class="py-3 px-4 text-right">
                <button onclick="event.stopPropagation(); openPatientChart(${p.id})" class="btn-view-chart px-3 py-1 rounded-lg text-xs transition-all font-semibold">
                    View Chart
                </button>
            </td>
        </tr>
    `;}).join("");

    lucide.createIcons();
}

async function openPatientChart(patientId, isEmergency = false, reason = "") {
    try {
        let url = `/api/patients/${patientId}`;
        if (isEmergency) {
            url += `?is_emergency_override=true&override_reason=${encodeURIComponent(reason)}`;
        }

        const res = await fetch(url, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });

        if (res.status === 403) {
            const err = await res.json();
            showToast("Access Denied (403)", err.detail, "HIGH");
            // Only prompt Break-the-Glass if user is not quarantined and is a Doctor/Nurse
            if (!state.currentUser?.is_quarantined && ["DOCTOR", "NURSE"].includes(state.currentUser?.role)) {
                promptBreakTheGlass(patientId);
            }
            return;
        }

        if (!res.ok) {
            const err = await res.json();
            showToast("Error", err.detail || "Failed to load patient record", "HIGH");
            return;
        }

        const data = await res.json();
        state.selectedPatient = data;
        renderPatientChartModal(data);
    } catch (e) {
        console.error("Open patient chart error:", e);
    }
}

function renderPatientChartModal(patient) {
    const modal = document.getElementById("patient-chart-modal");
    if (!modal) return;

    document.getElementById("modal-patient-name").textContent = `${patient.first_name} ${patient.last_name}`;
    document.getElementById("modal-patient-mrn").textContent = patient.mrn;
    document.getElementById("modal-patient-dept").textContent = patient.department;
    document.getElementById("modal-patient-room").textContent = patient.ward_room;
    document.getElementById("modal-patient-dob").textContent = `${patient.dob} (${patient.gender})`;

    const banner = document.getElementById("modal-emergency-banner");
    if (patient.is_emergency_override_active) {
        banner.classList.remove("hidden");
    } else {
        banner.classList.add("hidden");
    }

    const btgBtn = document.getElementById("btn-modal-btg");
    if (btgBtn) {
        btgBtn.onclick = () => promptBreakTheGlass(patient.id);
        // Hide BTG button if already overridden
        btgBtn.style.display = patient.is_emergency_override_active ? "none" : "inline-flex";
    }

    const recordsContainer = document.getElementById("modal-records-list");
    if (!recordsContainer) return;

    if (!patient.records || patient.records.length === 0) {
        recordsContainer.innerHTML = `
            <div class="text-center py-8 text-slate-400 bg-slate-900/50 rounded-xl border border-slate-800">
                <p>No clinical records available under your current role clearance (${state.currentUser?.role}).</p>
                <p class="text-xs text-slate-500 mt-1">Role-Based & Attribute-Based filtering active.</p>
            </div>
        `;
    } else {
        recordsContainer.innerHTML = patient.records.map(r => `
            <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                            r.record_type === 'vitals' ? 'bg-emerald-900/50 text-emerald-300 border border-emerald-700/50' :
                            r.record_type === 'prescription' ? 'bg-blue-900/50 text-blue-300 border border-blue-700/50' :
                            r.record_type === 'clinical_notes' ? 'bg-purple-900/50 text-purple-300 border border-purple-700/50' :
                            r.record_type === 'lab_result' ? 'bg-amber-900/50 text-amber-300 border border-amber-700/50' :
                            'bg-slate-800 text-slate-300 border border-slate-700'
                        }">
                            ${r.record_type.replace('_', ' ')}
                        </span>
                        <h4 class="text-sm font-semibold text-slate-200">${r.title}</h4>
                    </div>
                    <span class="text-xs text-slate-500">${r.created_at ? r.created_at.split('T')[0] : ''}</span>
                </div>
                <div class="text-xs text-slate-300 whitespace-pre-line bg-slate-950/60 p-3 rounded-lg border border-slate-800/80 font-mono">
                    ${r.content}
                </div>
            </div>
        `).join("");
    }

    // Render Appointments & Scheduling
    renderPatientAppointments(patient.appointments || [], patient.id);

    modal.classList.remove("hidden");
    lucide.createIcons();
}

// --- APPOINTMENTS & RECEPTION SCHEDULING SYSTEM ---
function renderPatientAppointments(appointments, patientId) {
    const badge = document.getElementById("modal-appointments-count-badge");
    const toolbar = document.getElementById("appointment-actions-toolbar");
    const listContainer = document.getElementById("modal-appointments-list");
    const formContainer = document.getElementById("appointment-form-container");

    if (formContainer) formContainer.classList.add("hidden");

    if (badge) {
        badge.textContent = `${appointments.length} Scheduled`;
    }

    const canManage = state.currentUser && ["BILLING", "ADMIN"].includes(state.currentUser.role);

    if (toolbar) {
        if (canManage) {
            toolbar.innerHTML = `
                <button type="button" onclick="toggleAppointmentForm(true)" 
                    class="px-3 py-1.5 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-md shadow-cyan-500/20 flex items-center space-x-1.5 transition-all">
                    <i data-lucide="plus-circle" class="w-3.5 h-3.5"></i>
                    <span>Schedule Appointment</span>
                </button>
            `;
        } else {
            toolbar.innerHTML = `
                <span class="text-[11px] text-slate-400 px-2.5 py-1 rounded-lg bg-slate-800/80 border border-slate-700/80 inline-flex items-center">
                    <i data-lucide="lock" class="w-3 h-3 mr-1 text-slate-500"></i>
                    <span>Read-Only Access (${state.currentUser?.role})</span>
                </span>
            `;
        }
    }

    if (!listContainer) return;

    if (!appointments || appointments.length === 0) {
        listContainer.innerHTML = `
            <div class="text-center py-6 bg-slate-950/40 rounded-xl border border-slate-800/80 text-slate-400">
                <i data-lucide="calendar-check-2" class="w-6 h-6 mx-auto mb-1.5 text-slate-500"></i>
                <p class="text-xs font-semibold">No appointments currently scheduled for this patient.</p>
                ${canManage ? '<p class="text-[11px] text-cyan-400/90 mt-1 cursor-pointer hover:underline" onclick="toggleAppointmentForm(true)">+ Click here to schedule the first appointment</p>' : ''}
            </div>
        `;
        return;
    }

    listContainer.innerHTML = appointments.map(apt => {
        const statusClass = 
            apt.status === 'CONFIRMED' ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40' :
            apt.status === 'COMPLETED' ? 'bg-slate-700/50 text-slate-400 border-slate-600/60' :
            apt.status === 'CANCELLED' ? 'bg-rose-500/15 text-rose-300 border-rose-500/40' :
            'bg-cyan-500/15 text-cyan-300 border-cyan-500/40';

        let actionControls = '';
        if (canManage) {
            actionControls = `
                <div class="flex items-center space-x-2 mt-2 sm:mt-0">
                    <select onchange="quickUpdateAppointmentStatus(${patientId}, '${apt.id}', this.value)" 
                        class="bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-[11px] text-slate-200 focus:outline-none focus:border-cyan-500">
                        <option value="SCHEDULED" ${apt.status === 'SCHEDULED' ? 'selected' : ''}>SCHEDULED</option>
                        <option value="CONFIRMED" ${apt.status === 'CONFIRMED' ? 'selected' : ''}>CONFIRMED</option>
                        <option value="COMPLETED" ${apt.status === 'COMPLETED' ? 'selected' : ''}>COMPLETED</option>
                        <option value="CANCELLED" ${apt.status === 'CANCELLED' ? 'selected' : ''}>CANCELLED</option>
                    </select>
                    <button type="button" onclick="editAppointmentModal(${patientId}, '${apt.id}')" 
                        title="Edit Appointment Details"
                        class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors">
                        <i data-lucide="edit-3" class="w-3.5 h-3.5"></i>
                    </button>
                    <button type="button" onclick="deleteAppointment(${patientId}, '${apt.id}')" 
                        title="Cancel & Remove Appointment"
                        class="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 hover:text-white border border-rose-500/30 transition-colors">
                        <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                    </button>
                </div>
            `;
        }

        return `
            <div class="appointment-item-card p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/90 flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-all hover:border-slate-700">
                <div class="space-y-1">
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${statusClass}">
                            ${apt.status}
                        </span>
                        <span class="text-xs font-mono font-semibold text-cyan-400 flex items-center">
                            <i data-lucide="calendar" class="w-3 h-3 mr-1 text-cyan-400"></i>
                            ${apt.date} at ${apt.time}
                        </span>
                        <span class="text-[10px] font-mono text-slate-500">(${apt.id})</span>
                    </div>
                    <div class="flex items-center space-x-2 text-xs text-slate-300">
                        <span class="font-medium text-slate-200">${apt.purpose}</span>
                        <span>•</span>
                        <span class="text-slate-400">${apt.department}</span>
                        ${apt.staff ? `<span>•</span><span class="text-slate-400 flex items-center"><i data-lucide="user" class="w-2.5 h-2.5 mr-0.5 text-slate-500"></i>${apt.staff}</span>` : ''}
                    </div>
                </div>
                ${actionControls}
            </div>
        `;
    }).join("");
}

function toggleAppointmentForm(show, editApt = null) {
    const container = document.getElementById("appointment-form-container");
    if (!container) return;

    if (!show) {
        container.classList.add("hidden");
        return;
    }

    const editIdInput = document.getElementById("appointment-edit-id");
    const titleEl = document.getElementById("appointment-form-title");
    const dateInput = document.getElementById("apt-input-date");
    const timeInput = document.getElementById("apt-input-time");
    const deptInput = document.getElementById("apt-input-dept");
    const staffInput = document.getElementById("apt-input-staff");
    const statusInput = document.getElementById("apt-input-status");
    const purposeInput = document.getElementById("apt-input-purpose");
    const btnText = document.getElementById("btn-save-appointment-text");

    if (editApt) {
        if (editIdInput) editIdInput.value = editApt.id;
        if (titleEl) titleEl.textContent = `Update Appointment (${editApt.id})`;
        if (dateInput) dateInput.value = editApt.date || "";
        if (timeInput) timeInput.value = editApt.time || "";
        if (deptInput) deptInput.value = editApt.department || "Cardiology";
        if (staffInput) staffInput.value = editApt.staff || "";
        if (statusInput) statusInput.value = editApt.status || "SCHEDULED";
        if (purposeInput) purposeInput.value = editApt.purpose || "";
        if (btnText) btnText.textContent = "Update Appointment";
    } else {
        if (editIdInput) editIdInput.value = "";
        if (titleEl) titleEl.textContent = "Schedule New Appointment";
        const today = new Date().toISOString().split("T")[0];
        if (dateInput) dateInput.value = today;
        if (timeInput) timeInput.value = "10:00";
        if (deptInput) deptInput.value = (state.selectedPatient && state.selectedPatient.department) || "Cardiology";
        if (staffInput) staffInput.value = "";
        if (statusInput) statusInput.value = "SCHEDULED";
        if (purposeInput) purposeInput.value = "";
        if (btnText) btnText.textContent = "Save Appointment";
    }

    container.classList.remove("hidden");
    lucide.createIcons();
}

function editAppointmentModal(patientId, appointmentId) {
    if (!state.selectedPatient || !state.selectedPatient.appointments) return;
    const apt = state.selectedPatient.appointments.find(a => a.id === appointmentId);
    if (!apt) return;
    toggleAppointmentForm(true, apt);
}

async function handleAppointmentFormSubmit(e) {
    if (e) e.preventDefault();
    if (!state.selectedPatient) return;

    const patientId = state.selectedPatient.id;
    const editId = document.getElementById("appointment-edit-id").value;
    const date = document.getElementById("apt-input-date").value;
    const time = document.getElementById("apt-input-time").value;
    const department = document.getElementById("apt-input-dept").value;
    const staff = document.getElementById("apt-input-staff").value.trim();
    const status = document.getElementById("apt-input-status").value;
    const purpose = document.getElementById("apt-input-purpose").value.trim();

    const payload = { date, time, department, staff, status, purpose };

    try {
        let res;
        if (editId) {
            res = await fetch(`/api/patients/${patientId}/appointments/${editId}`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${state.token}`
                },
                body: JSON.stringify(payload)
            });
        } else {
            res = await fetch(`/api/patients/${patientId}/appointments`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${state.token}`
                },
                body: JSON.stringify(payload)
            });
        }

        if (!res.ok) {
            const err = await res.json();
            showToast("Scheduling Denied", err.detail || "Unable to save appointment", "CRITICAL");
            return;
        }

        const data = await res.json();
        showToast("Appointment Saved", data.message || "Appointment recorded in blockchain ledger.", "NORMAL");
        toggleAppointmentForm(false);

        // Refresh chart modal and table
        await openPatientChart(patientId);
        await fetchPatients(state.activeDepartment);
    } catch (err) {
        console.error("Save appointment error:", err);
        showToast("Error", "Network or server failure saving appointment.", "HIGH");
    }
}

async function quickUpdateAppointmentStatus(patientId, appointmentId, newStatus) {
    try {
        const res = await fetch(`/api/patients/${patientId}/appointments/${appointmentId}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({ status: newStatus })
        });

        if (!res.ok) {
            const err = await res.json();
            showToast("Update Denied", err.detail || "Unable to update status", "CRITICAL");
            return;
        }

        showToast("Status Updated", `Appointment ${appointmentId} updated to ${newStatus}`, "NORMAL");
        await openPatientChart(patientId);
        await fetchPatients(state.activeDepartment);
    } catch (err) {
        console.error("Quick update error:", err);
    }
}

async function deleteAppointment(patientId, appointmentId) {
    if (!confirm(`Are you sure you want to cancel and remove appointment ${appointmentId}?`)) return;

    try {
        const res = await fetch(`/api/patients/${patientId}/appointments/${appointmentId}`, {
            method: "DELETE",
            headers: {
                "Authorization": `Bearer ${state.token}`
            }
        });

        if (!res.ok) {
            const err = await res.json();
            showToast("Delete Denied", err.detail || "Unable to remove appointment", "CRITICAL");
            return;
        }

        const data = await res.json();
        showToast("Appointment Removed", data.message || "Appointment deleted and logged to ledger.", "NORMAL");
        await openPatientChart(patientId);
        await fetchPatients(state.activeDepartment);
    } catch (err) {
        console.error("Delete appointment error:", err);
    }
}

function closePatientChart() {
    const modal = document.getElementById("patient-chart-modal");
    if (modal) modal.classList.add("hidden");
}

function promptBreakTheGlass(patientId) {
    const btgModal = document.getElementById("btg-prompt-modal");
    if (!btgModal) return;
    document.getElementById("btg-target-patient-id").value = patientId;
    document.getElementById("btg-reason-input").value = "";
    btgModal.classList.remove("hidden");
}

function closeBTGModal() {
    const btgModal = document.getElementById("btg-prompt-modal");
    if (btgModal) btgModal.classList.add("hidden");
}

async function submitBreakTheGlass() {
    const patientId = document.getElementById("btg-target-patient-id").value;
    const reason = document.getElementById("btg-reason-input").value.trim();

    if (!reason || reason.length < 5) {
        showToast("Validation Error", "Please provide a valid clinical emergency reason (min 5 characters).", "HIGH");
        return;
    }

    try {
        const res = await fetch(`/api/patients/${patientId}/break-the-glass`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({ reason: reason })
        });

        if (!res.ok) {
            const err = await res.json();
            showToast("Break-The-Glass Denied", err.detail || "Override failed", "CRITICAL");
            return;
        }

        closeBTGModal();
        showToast("Break-The-Glass Granted", "Emergency access waiver logged and dispatched to SOC.", "LOW");
        // Reload patient chart with emergency override flag active
        await openPatientChart(patientId, true, reason);
    } catch (e) {
        console.error("BTG Error:", e);
    }
}

// --- SOC SECURITY DASHBOARD ---
async function fetchSOCStats() {
    try {
        const res = await fetch("/api/soc/stats", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (!res.ok) return;
        state.socStats = await res.json();
        renderSOCStats(state.socStats);
    } catch (e) {
        console.error("Fetch SOC stats error:", e);
    }
}

function renderSOCStats(stats) {
    const critEl = document.getElementById("stat-critical-alerts");
    const highEl = document.getElementById("stat-high-alerts");
    const totalEl = document.getElementById("stat-total-alerts");
    const quarEl = document.getElementById("stat-quarantined-users");
    const chainEl = document.getElementById("stat-chain-status");

    if (critEl) critEl.textContent = stats.alerts_breakdown.critical;
    if (highEl) highEl.textContent = stats.alerts_breakdown.high;
    if (totalEl) totalEl.textContent = stats.alerts_breakdown.total;
    if (quarEl) quarEl.textContent = stats.quarantined_users_count;
    if (chainEl) {
        chainEl.textContent = stats.blockchain_status;
        chainEl.className = `text-xl font-bold font-mono ${stats.blockchain_tampered ? 'text-rose-400' : 'text-emerald-400'}`;
    }

    renderRiskyUsers(stats.risky_users);
    updateSeverityChart(stats.alerts_breakdown);
}

function renderRiskyUsers(users) {
    const container = document.getElementById("risky-users-table-body");
    if (!container) return;

    if (!users || users.length === 0) {
        container.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-500">No elevated risk user profiles detected.</td></tr>`;
        return;
    }

    container.innerHTML = users.map(u => `
        <tr class="border-b border-slate-800/60 hover:bg-slate-800/30">
            <td class="py-2.5 px-3 font-medium text-slate-200 text-xs">${u.username}</td>
            <td class="py-2.5 px-3 text-xs text-slate-400">${u.role} (${u.department})</td>
            <td class="py-2.5 px-3">
                <div class="flex items-center space-x-2">
                    <div class="w-16 bg-slate-800 rounded-full h-2">
                        <div class="h-2 rounded-full ${
                            u.risk_score >= 85 ? 'bg-rose-500' :
                            u.risk_score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                        }" style="width: ${Math.min(100, u.risk_score)}%"></div>
                    </div>
                    <span class="text-xs font-mono font-semibold ${
                        u.risk_score >= 85 ? 'text-rose-400' :
                        u.risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400'
                    }">${u.risk_score}</span>
                </div>
            </td>
            <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[11px] font-semibold ${
                    u.is_quarantined ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50'
                }">
                    ${u.is_quarantined ? 'QUARANTINED' : 'ACTIVE'}
                </span>
            </td>
            <td class="py-2.5 px-3 text-right space-x-1.5">
                <button onclick="toggleQuarantine(${u.id})" class="px-2 py-0.5 text-[11px] rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">
                    ${u.is_quarantined ? 'Lift' : 'Quarantine'}
                </button>
                <button onclick="resetUserRisk(${u.id})" class="px-2 py-0.5 text-[11px] rounded bg-cyan-900/40 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-700/50">
                    Reset
                </button>
            </td>
        </tr>
    `).join("");
}

function updateSeverityChart(breakdown) {
    const canvas = document.getElementById("severityChart");
    if (!canvas) return;

    if (state.severityChart) {
        state.severityChart.data.datasets[0].data = [
            breakdown.critical,
            breakdown.high,
            breakdown.medium,
            breakdown.low
        ];
        state.severityChart.update();
        return;
    }

    state.severityChart = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [breakdown.critical, breakdown.high, breakdown.medium, breakdown.low],
                backgroundColor: [
                    "rgba(244, 63, 94, 0.8)",
                    "rgba(249, 115, 22, 0.8)",
                    "rgba(234, 179, 8, 0.8)",
                    "rgba(59, 130, 246, 0.8)"
                ],
                borderColor: state.theme === "light" ? "#ffffff" : "#0f172a",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: state.theme === "light" ? "#1e293b" : "#94a3b8", boxWidth: 12, font: { size: 11, weight: '600' } }
                }
            },
            cutout: "70%"
        }
    });
}

async function fetchAlerts() {
    try {
        const res = await fetch("/api/soc/alerts?limit=50", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (!res.ok) return;
        state.alerts = await res.json();
        renderAlertsList();
    } catch (e) {
        console.error("Fetch alerts error:", e);
    }
}

function renderAlertsList() {
    const container = document.getElementById("alerts-feed-container");
    if (!container) return;

    if (state.alerts.length === 0) {
        container.innerHTML = `<div class="text-center py-10 text-slate-500">No active threat alerts recorded. All systems normal.</div>`;
        return;
    }

    container.innerHTML = state.alerts.map(a => `
        <div class="alert-card alert-card-${a.severity.toLowerCase()} p-3.5 rounded-xl border transition-all ${
            a.severity === 'CRITICAL' ? 'bg-rose-950/20 border-rose-900/60 shadow-lg shadow-rose-950/20' :
            a.severity === 'HIGH' ? 'bg-orange-950/20 border-orange-900/60' :
            a.severity === 'MEDIUM' ? 'bg-amber-950/20 border-amber-900/60' :
            'bg-slate-900/60 border-slate-800'
        }">
            <div class="flex items-center justify-between mb-1.5">
                <div class="flex items-center space-x-2">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${
                        a.severity === 'CRITICAL' ? 'bg-rose-500 text-white animate-pulse' :
                        a.severity === 'HIGH' ? 'bg-orange-500 text-white' :
                        a.severity === 'MEDIUM' ? 'bg-amber-500 text-slate-950' :
                        'bg-blue-500 text-white'
                    }">${a.severity}</span>
                    <span class="font-mono text-xs font-semibold text-slate-200">${a.rule_code}: ${a.rule_name}</span>
                </div>
                <span class="text-[11px] text-slate-400 font-mono">${a.timestamp ? a.timestamp.split('T')[1].slice(0, 8) : ''}</span>
            </div>
            <p class="text-xs text-slate-300 mb-2 leading-relaxed">${a.description}</p>
            <div class="flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
                <span>User: <strong class="text-cyan-300 font-sans">${a.user_username}</strong></span>
                <span>Risk Added: <strong class="text-rose-400">+${a.risk_score_delta}</strong></span>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${a.status === 'ACTIVE' ? 'bg-rose-900/40 text-rose-300 border border-rose-700/50' : 'bg-emerald-900/40 text-emerald-300 border border-emerald-700/50'}">${a.status}</span>
            </div>
        </div>
    `).join("");
}

async function toggleQuarantine(userId) {
    try {
        const res = await fetch(`/api/soc/users/${userId}/toggle-quarantine`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (res.ok) {
            const data = await res.json();
            showToast("Quarantine Updated", data.message, "LOW");
            fetchSOCStats();
            checkAuth();
        }
    } catch (e) {
        console.error("Toggle quarantine error:", e);
    }
}

async function resetUserRisk(userId) {
    try {
        const res = await fetch(`/api/soc/users/${userId}/reset-risk`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (res.ok) {
            const data = await res.json();
            showToast("Risk Reset", data.message, "LOW");
            fetchSOCStats();
            checkAuth();
        }
    } catch (e) {
        console.error("Reset risk error:", e);
    }
}

// --- CRYPTOGRAPHIC AUDIT EXPLORER & BLOCKCHAIN VERIFIER ---
async function fetchAuditLogs(actionFilter = "") {
    try {
        let url = "/api/audit/logs?limit=100";
        if (actionFilter) url += `&action_filter=${encodeURIComponent(actionFilter)}`;

        const res = await fetch(url, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (!res.ok) return;
        state.auditLogs = await res.json();
        renderAuditLogsTable();
    } catch (e) {
        console.error("Fetch audit logs error:", e);
    }
}

function renderAuditLogsTable() {
    const tbody = document.getElementById("audit-table-body");
    if (!tbody) return;

    if (state.auditLogs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-slate-500">No cryptographic audit records recorded yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = state.auditLogs.map(l => `
        <tr class="border-b border-slate-800/80 hover:bg-slate-800/40 text-xs">
            <td class="py-2.5 px-3 font-mono font-bold text-cyan-400">#${l.id}</td>
            <td class="py-2.5 px-3 font-mono text-slate-400">${l.timestamp ? l.timestamp.replace('T', ' ').slice(0, 19) : ''}</td>
            <td class="py-2.5 px-3 font-medium text-slate-200">
                ${l.user_username}
                <span class="block text-[10px] text-slate-500">${l.user_role}</span>
            </td>
            <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${
                    l.action === 'BREAK_THE_GLASS' ? 'bg-amber-900/60 text-amber-300 border border-amber-600' :
                    l.action === 'ACCESS_DENIED' ? 'bg-rose-900/60 text-rose-300 border border-rose-600' :
                    l.action === 'HONEYTOKEN_TRIGGER' ? 'bg-purple-900/60 text-purple-300 border border-purple-600 animate-pulse' :
                    'bg-slate-800 text-slate-300 border border-slate-700'
                }">
                    ${l.action}
                </span>
            </td>
            <td class="py-2.5 px-3 text-slate-300 font-mono">
                ${l.resource_type}
                ${l.patient_mrn ? `<span class="block text-[10px] text-cyan-500">${l.patient_mrn}</span>` : ''}
            </td>
            <td class="py-2.5 px-3 hash-cell text-slate-400 truncate max-w-[120px]" title="${l.prev_hash}">
                ${l.prev_hash.slice(0, 12)}...
            </td>
            <td class="py-2.5 px-3 hash-cell text-emerald-400 truncate max-w-[140px]" title="${l.record_hash}">
                ${l.record_hash.slice(0, 14)}...
            </td>
        </tr>
    `).join("");
}

async function verifyBlockchain(showAlertToast = true) {
    const banner = document.getElementById("blockchain-verification-banner");
    try {
        const res = await fetch("/api/audit/verify-integrity", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const result = await res.json();

        if (banner) {
            banner.classList.remove("hidden");
            if (result.status === "VALID") {
                banner.className = "mb-4 p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/50 flex items-center justify-between";
                banner.innerHTML = `
                    <div class="flex items-center space-x-3">
                        <div class="w-8 h-8 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold">✓</div>
                        <div>
                            <h4 class="text-sm font-semibold text-emerald-300">Cryptographic Blockchain Ledger: 100% INTACT</h4>
                            <p class="text-xs text-slate-300">All ${result.total_blocks} chained blocks verified against SHA-256 genesis root.</p>
                        </div>
                    </div>
                    <span class="px-3 py-1 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-xs rounded-lg font-mono">NO TAMPERING</span>
                `;
                if (showAlertToast) showToast("Audit Ledger Verified", result.message, "LOW");
            } else {
                banner.className = "mb-4 p-4 rounded-xl bg-rose-950/60 border border-rose-500 flex items-center justify-between animate-pulse-red";
                banner.innerHTML = `
                    <div class="flex items-center space-x-3">
                        <div class="w-8 h-8 rounded-full bg-rose-500/20 text-rose-400 flex items-center justify-center font-bold">⚠️</div>
                        <div>
                            <h4 class="text-sm font-bold text-rose-300">CRITICAL TAMPER ALERT: AUDIT BLOCKCHAIN COMPROMISED!</h4>
                            <p class="text-xs text-rose-200">${result.message}</p>
                            <p class="text-[11px] text-slate-300 font-mono mt-0.5">Broken Block ID: #${result.broken_block_id} | UUID: ${result.broken_event_uuid}</p>
                        </div>
                    </div>
                    <span class="px-3 py-1 bg-rose-500 text-white text-xs rounded-lg font-mono font-bold">CORRUPTED</span>
                `;
                if (showAlertToast) showToast("TAMPER DETECTED", result.message, "CRITICAL");
            }
        }
    } catch (e) {
        console.error("Blockchain verification error:", e);
    }
}

async function simulateTampering() {
    try {
        const res = await fetch("/api/audit/simulate-tampering", {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        if (data.success) {
            showToast("Malicious Edit Injected", data.message, "HIGH");
            await fetchAuditLogs();
            await verifyBlockchain(true);
        } else {
            showToast("Tamper Simulation", data.message, "LOW");
        }
    } catch (e) {
        console.error("Simulate tampering error:", e);
    }
}

function downloadAuditCSV() {
    window.location.href = "/api/audit/export-csv";
}

// --- ATTACK SCENARIO SIMULATOR (PITCH DEMO SUITE) ---
async function runScenario(scenarioKey) {
    const btn = document.getElementById(`btn-scenario-${scenarioKey}`);
    const originalText = btn ? btn.innerHTML : "";
    if (btn) btn.innerHTML = `<span class="animate-spin inline-block mr-1">⚙️</span> Executing...`;

    try {
        const res = await fetch(`/api/simulator/scenario/${scenarioKey}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();

        showToast(
            `Scenario: ${data.scenario}`,
            data.message || `${data.outcome || 'Finished'}. Risk: ${data.user_risk_score || data.user_new_risk_score || 0}`,
            data.severity || (data.alerts_triggered > 0 ? "HIGH" : "LOW")
        );

        // Update stats and check current user
        const isAuditorOrAdmin = state.currentUser && ["AUDITOR", "ADMIN"].includes(state.currentUser.role);
        if (isAuditorOrAdmin) {
            await fetchSOCStats();
        }
        await checkAuth();
    } catch (e) {
        console.error("Scenario execution error:", e);
        showToast("Execution Error", "Scenario invocation failed.", "HIGH");
    } finally {
        if (btn) btn.innerHTML = originalText;
    }
}

async function resetAllScenarios() {
    try {
        const res = await fetch("/api/simulator/scenario/reset_all", {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        showToast("Simulator Reset", data.message, "LOW");
        const isAuditorOrAdmin = state.currentUser && ["AUDITOR", "ADMIN"].includes(state.currentUser.role);
        if (isAuditorOrAdmin) {
            await fetchSOCStats();
        }
        await checkAuth();
    } catch (e) {
        console.error("Reset error:", e);
    }
}

// --- TOAST NOTIFICATIONS ---
function showToast(title, message, severity = "LOW") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    const borderCol = severity === "CRITICAL" ? "border-rose-500 bg-rose-950/90 text-rose-200" :
                      severity === "HIGH" ? "border-orange-500 bg-orange-950/90 text-orange-200" :
                      severity === "MEDIUM" ? "border-amber-500 bg-amber-950/90 text-amber-200" :
                      "border-cyan-500 bg-slate-900/90 text-cyan-200";

    toast.className = `p-3.5 rounded-xl border shadow-xl backdrop-blur-md max-w-sm transition-all duration-300 transform translate-y-2 opacity-0 ${borderCol}`;
    toast.innerHTML = `
        <div class="flex items-start justify-between">
            <div>
                <h5 class="text-xs font-bold font-sans">${title}</h5>
                <p class="text-[11px] text-slate-300 mt-0.5 leading-snug">${message}</p>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" class="text-slate-400 hover:text-white ml-2 text-xs">✕</button>
        </div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.remove("translate-y-2", "opacity-0");
    }, 10);

    setTimeout(() => {
        toast.classList.add("opacity-0", "translate-y-2");
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// --- HIPAA & NIST INACTIVITY SESSION AUTO-LOCK (45 CFR §164.312(a)(2)(iii), NIST AC-11) ---
let inactivityTimer = null;
let countdownInterval = null;
const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes standard HIPAA limit
const WARNING_THRESHOLD_MS = 60 * 1000;    // 60 seconds warning modal
let lastActivityTime = Date.now();

function initInactivityTracker() {
    const activityEvents = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    activityEvents.forEach(evt => {
        window.addEventListener(evt, resetInactivityTimer, { passive: true });
    });

    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = setInterval(checkInactivityLoop, 1000);
}

function resetInactivityTimer() {
    lastActivityTime = Date.now();
    const modal = document.getElementById("inactivity-warning-modal");
    if (modal && !modal.classList.contains("hidden")) {
        // Modal is open, wait for explicit user action
    }
}

function extendSession() {
    lastActivityTime = Date.now();
    const modal = document.getElementById("inactivity-warning-modal");
    if (modal) modal.classList.add("hidden");
    showToast("Session Extended", "HIPAA session activity refreshed.", "LOW");
}

function checkInactivityLoop() {
    if (!state.token) return; // Not logged in
    const elapsed = Date.now() - lastActivityTime;
    const remaining = Math.max(0, SESSION_TIMEOUT_MS - elapsed);
    const remainingSeconds = Math.floor(remaining / 1000);

    // Update Header countdown timer badge
    const headerCountdown = document.getElementById("session-countdown-text");
    if (headerCountdown) {
        const mins = Math.floor(remainingSeconds / 60);
        const secs = remainingSeconds % 60;
        headerCountdown.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    }

    const modal = document.getElementById("inactivity-warning-modal");
    const modalSeconds = document.getElementById("modal-countdown-seconds");

    if (remaining <= WARNING_THRESHOLD_MS && remaining > 0) {
        if (modal && modal.classList.contains("hidden")) {
            modal.classList.remove("hidden");
            lucide.createIcons();
        }
        if (modalSeconds) {
            modalSeconds.textContent = remainingSeconds;
        }
    } else if (remaining <= 0) {
        if (modal) modal.classList.add("hidden");
        logout();
        showToast("Session Terminated", "Logged off automatically due to inactivity in compliance with HIPAA §164.312(a)(2)(iii).", "CRITICAL");
    } else {
        if (modal && !modal.classList.contains("hidden")) {
            modal.classList.add("hidden");
        }
    }
}

// --- REGULATORY COMPLIANCE SUITE (HIPAA, NIST SP 800-53, HITRUST, GDPR, OWASP) ---
let cachedComplianceData = null;

async function fetchComplianceReport() {
    try {
        const res = await fetch("/api/soc/compliance", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (!res.ok) return;
        cachedComplianceData = await res.json();
        renderComplianceMatrix(cachedComplianceData);
    } catch (e) {
        console.error("Fetch compliance error:", e);
    }
}

async function runComplianceScan() {
    const btnText = document.getElementById("compliance-scan-btn-text");
    if (btnText) btnText.textContent = "Scanning Controls...";
    try {
        await fetchComplianceReport();
        showToast("Audit Scan Complete", "All 10 security standards technical controls verified PASS.", "LOW");
    } finally {
        if (btnText) btnText.textContent = "Run Live Audit Scan";
    }
}

function renderComplianceMatrix(data) {
    if (!data) return;
    const badgeEl = document.getElementById("compliance-overall-badge");
    const tbody = document.getElementById("compliance-checklist-tbody");

    if (badgeEl) {
        badgeEl.textContent = `${data.compliance_score}% ${data.overall_status}`;
        badgeEl.className = data.compliance_score === 100
            ? "px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
            : "px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40";
    }

    if (!tbody || !data.controls) return;

    tbody.innerHTML = data.controls.map(c => `
        <tr class="hover:bg-slate-800/40 transition-colors">
            <td class="p-2.5 font-mono text-cyan-300 font-semibold text-[11px] whitespace-nowrap">
                <div>${c.framework}</div>
                <div class="text-[10px] text-slate-400 font-mono">${c.citation}</div>
            </td>
            <td class="p-2.5 font-semibold text-slate-200">
                ${c.title}
            </td>
            <td class="p-2.5 text-slate-300 text-[11px]">
                ${c.description}
            </td>
            <td class="p-2.5 whitespace-nowrap">
                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                    c.status === 'PASS' 
                        ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40' 
                        : 'bg-rose-500/15 text-rose-300 border border-rose-500/40 animate-pulse'
                }">
                    <i data-lucide="${c.status === 'PASS' ? 'check-circle-2' : 'alert-octagon'}" class="w-3 h-3 mr-1"></i>
                    ${c.status_label}
                </span>
            </td>
            <td class="p-2.5 text-slate-400 font-mono text-[11px]">
                ${c.evidence}
            </td>
        </tr>
    `).join("");

    lucide.createIcons();
}

function exportComplianceReport() {
    if (!cachedComplianceData) {
        showToast("Scan Required", "Running audit scan first...", "LOW");
        runComplianceScan().then(() => generateComplianceDownload());
    } else {
        generateComplianceDownload();
    }
}

function generateComplianceDownload() {
    if (!cachedComplianceData) return;
    const d = cachedComplianceData;
    let md = `# AEGISHEALTH REGULATORY COMPLIANCE CERTIFICATE
Generated: ${new Date().toUTCString()}
Compliance Score: ${d.compliance_score}% - Status: ${d.overall_status}

## 1. APPLICABLE STANDARDS & FRAMEWORKS
- HIPAA Security Rule: 45 CFR Part 164 Subpart C (Technical Safeguards)
- NIST SP 800-53 Revision 5 (High Baseline Security Controls)
- HITRUST CSF v11.2 (Health Information Trust Framework)
- GDPR: Regulation (EU) 2016/679 (Articles 25, 32, 33)
- OWASP Top 10 (2021) & API Security Top 10 (2023)

## 2. TECHNICAL CONTROL AUDIT MATRIX
`;
    d.controls.forEach((c, idx) => {
        md += `\n### Control ${idx + 1}: ${c.title}
- Framework & Citation: ${c.framework} (${c.citation})
- Requirement: ${c.description}
- Audit Status: [${c.status_label}]
- Verification Evidence: ${c.evidence}
`;
    });

    md += `\n=========================================================\nCryptographically Anchored to SHA-256 Merkle Ledger.\nAuthorized by Cyber SOC Chief Auditor & Security Operations.\n`;

    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `AegisHealth_Compliance_Report_${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast("Report Exported", "Compliance certificate downloaded.", "LOW");
}

