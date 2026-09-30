// State Management
let authToken = localStorage.getItem("cns_token") || null;
let currentUser = null;
let selectedFileToEncrypt = null;

let chartTimeline = null;
let chartPie = null;

// Initialize App
document.addEventListener("DOMContentLoaded", () => {
    checkAuth();
    setupDragAndDrop();
});

// View Navigation & SPA Router
function switchView(viewName) {
    // Hide all view sections
    document.querySelectorAll(".view-section").forEach(el => {
        el.classList.remove("active-view");
    });

    // Update active nav button
    document.querySelectorAll(".nav-item button").forEach(btn => {
        btn.classList.remove("active");
    });

    const targetView = document.getElementById(`view${capitalize(viewName)}`);
    const targetNav = document.getElementById(`nav${capitalize(viewName)}`);

    if (targetView) targetView.classList.add("active-view");
    if (targetNav) targetNav.classList.add("active");

    // Update Top Header Title
    const titleMap = {
        dashboard: '<i class="fa-solid fa-chart-line"></i> Security Dashboard',
        encrypt: '<i class="fa-solid fa-lock"></i> Encrypt File (AES-256 + RSA-2048)',
        decrypt: '<i class="fa-solid fa-unlock-keyhole"></i> Decrypt File & SHA-256 Check',
        threat: '<i class="fa-solid fa-brain"></i> AI Threat Detection Engine',
        logs: '<i class="fa-solid fa-shield-virus"></i> Security Audit Logs',
        info: '<i class="fa-solid fa-graduation-cap"></i> CNS Project Information'
    };
    if (titleMap[viewName]) {
        document.getElementById("pageTitle").innerHTML = titleMap[viewName];
    }

    // Trigger View-Specific Data Fetching
    if (viewName === "dashboard") {
        loadDashboardStats();
    } else if (viewName === "decrypt") {
        loadEncryptedFiles();
    } else if (viewName === "threat") {
        loadThreatStatus();
    } else if (viewName === "logs") {
        loadSecurityLogs();
    }
}

function capitalize(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
}

// Authentication Handlers
async function checkAuth() {
    if (!authToken) {
        showLandingView();
        return;
    }
    try {
        const res = await fetch("/api/auth/me", {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        if (res.ok) {
            currentUser = await res.json();
            showAppView();
        } else {
            logout();
        }
    } catch (err) {
        console.error("Auth check failed:", err);
        showLandingView();
    }
}

function showLandingView() {
    document.getElementById("sidebar").style.display = "none";
    document.getElementById("topHeader").style.display = "none";
    document.getElementById("mainContent").style.marginLeft = "0";
    switchView("landing");
}

function showAppView() {
    document.getElementById("sidebar").style.display = "flex";
    document.getElementById("topHeader").style.display = "flex";
    document.getElementById("mainContent").style.marginLeft = "270px";
    document.getElementById("displayUsername").innerText = currentUser.username;
    switchView("dashboard");
    loadThreatStatusHeader();
}

function showAuthView(tab = 'login') {
    document.querySelectorAll(".view-section").forEach(el => el.classList.remove("active-view"));
    document.getElementById("viewAuth").classList.add("active-view");
    switchAuthTab(tab);
}

function switchAuthTab(tab) {
    const formLogin = document.getElementById("formLogin");
    const formRegister = document.getElementById("formRegister");
    const tabLogin = document.getElementById("tabBtnLogin");
    const tabRegister = document.getElementById("tabBtnRegister");

    if (tab === "login") {
        formLogin.style.display = "block";
        formRegister.style.display = "none";
        tabLogin.style.borderColor = "var(--accent-cyan)";
        tabLogin.style.color = "var(--accent-cyan)";
        tabRegister.style.borderColor = "var(--border-color)";
        tabRegister.style.color = "var(--text-muted)";
    } else {
        formLogin.style.display = "none";
        formRegister.style.display = "block";
        tabRegister.style.borderColor = "var(--accent-cyan)";
        tabRegister.style.color = "var(--accent-cyan)";
        tabLogin.style.borderColor = "var(--border-color)";
        tabLogin.style.color = "var(--text-muted)";
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById("loginUsername").value;
    const password = document.getElementById("loginPassword").value;

    try {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) {
            authToken = data.access_token;
            localStorage.setItem("cns_token", authToken);
            showToast("Login successful!", "success");
            await checkAuth();
        } else {
            showToast(data.detail || "Login failed", "error");
        }
    } catch (err) {
        showToast("Server communication error", "error");
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById("regUsername").value;
    const email = document.getElementById("regEmail").value;
    const password = document.getElementById("regPassword").value;
    const confirmPassword = document.getElementById("regConfirmPassword").value;

    if (password !== confirmPassword) {
        showToast("Passwords do not match!", "error");
        return;
    }

    try {
        const res = await fetch("/api/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password })
        });
        const data = await res.json();
        if (res.ok) {
            showToast("Registration successful! Please login.", "success");
            switchAuthTab("login");
            document.getElementById("loginUsername").value = username;
        } else {
            showToast(data.detail || "Registration failed", "error");
        }
    } catch (err) {
        showToast("Server error during registration", "error");
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem("cns_token");
    showToast("Logged out of session", "success");
    showLandingView();
}

// File Selection & Drag-and-Drop Handlers
function setupDragAndDrop() {
    const dropzone = document.getElementById("dropzone");
    if (!dropzone) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.remove('dragover'), false);
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            setSelectedFile(files[0]);
        }
    });
}

function handleFileSelect(e) {
    if (e.target.files.length > 0) {
        setSelectedFile(e.target.files[0]);
    }
}

function setSelectedFile(file) {
    selectedFileToEncrypt = file;
    document.getElementById("selectedFileText").innerHTML = `
        <strong style="color: var(--accent-cyan);">${file.name}</strong> (${(file.size / 1024).toFixed(2)} KB)
    `;
    document.getElementById("btnEncrypt").disabled = false;
}

// Encryption Execution
async function executeEncryption() {
    if (!selectedFileToEncrypt) {
        showToast("Please select a file first", "error");
        return;
    }

    const btn = document.getElementById("btnEncrypt");
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Encrypting...`;

    const formData = new FormData();
    formData.append("file", selectedFileToEncrypt);

    try {
        const res = await fetch("/api/encrypt", {
            method: "POST",
            headers: { "Authorization": `Bearer ${authToken}` },
            body: formData
        });
        const data = await res.json();
        if (res.ok) {
            showToast("Hybrid Encryption complete!", "success");
            const resCard = document.getElementById("encryptResultCard");
            resCard.style.display = "block";
            document.getElementById("resOriginalName").innerText = data.original_filename;
            document.getElementById("resEncName").innerText = data.encrypted_filename;
            document.getElementById("resShaHash").innerText = data.sha256_hash;

            // Reset selection
            selectedFileToEncrypt = null;
            document.getElementById("selectedFileText").innerText = "Supports all file types (Documents, Images, Archives, Binary Data)";
            loadThreatStatusHeader();
        } else {
            showToast(data.detail || "Encryption failed", "error");
        }
    } catch (err) {
        showToast("Error uploading file for encryption", "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-lock"></i> Execute Hybrid Encryption`;
    }
}

// Decryption Handler
async function loadEncryptedFiles() {
    const tbody = document.getElementById("filesTableBody");
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</td></tr>`;

    try {
        const res = await fetch("/api/files", {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const files = await res.json();
        if (res.ok) {
            if (files.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No encrypted files found in vault. Encrypt a file first.</td></tr>`;
                return;
            }
            tbody.innerHTML = files.map(f => `
                <tr>
                    <td>#${f.id}</td>
                    <td><strong>${f.original_filename}</strong></td>
                    <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">${f.sha256_hash.substring(0, 16)}...</td>
                    <td>${(f.file_size / 1024).toFixed(1)} KB</td>
                    <td style="font-size: 0.8rem; color: var(--text-muted);">${new Date(f.encryption_timestamp).toLocaleString()}</td>
                    <td>
                        <button class="btn-cyber-outline" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;" onclick="requestDecryption(${f.id})">
                            <i class="fa-solid fa-unlock"></i> Decrypt
                        </button>
                    </td>
                </tr>
            `).join('');
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--status-threat);">Error loading files</td></tr>`;
    }
}

async function requestDecryption(fileId) {
    const resCard = document.getElementById("decryptResultCard");
    resCard.style.display = "block";
    document.getElementById("decMessage").innerText = "Executing AI threat assessment & RSA-2048 key unwrap...";
    document.getElementById("btnDownloadDecrypted").style.display = "none";

    try {
        const res = await fetch(`/api/decrypt/${fileId}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();

        const statusBadge = document.getElementById("decStatusBadge");
        document.getElementById("decMessage").innerText = data.message;
        document.getElementById("decOriginalHash").innerText = data.original_hash;
        document.getElementById("decComputedHash").innerText = data.computed_hash;
        document.getElementById("decAnomalyScore").innerText = `${data.anomaly_score} (${data.threat_level})`;

        if (data.status === "SUCCESS" && data.integrity_verified) {
            statusBadge.className = "badge-threat badge-low";
            statusBadge.innerText = "VERIFIED ✅";
            showToast("Decryption successful & integrity verified!", "success");

            if (data.download_url) {
                const btnDl = document.getElementById("btnDownloadDecrypted");
                btnDl.href = data.download_url;
                btnDl.style.display = "inline-flex";
            }
        } else {
            statusBadge.className = "badge-threat badge-high";
            statusBadge.innerText = "ALERT 🚨";
            showToast(data.message, "error");
        }

        loadThreatStatusHeader();

    } catch (err) {
        showToast("Error processing decryption request", "error");
    }
}

// AI Threat Status Handlers
async function loadThreatStatusHeader() {
    if (!authToken) return;
    try {
        const res = await fetch("/api/threat-detection/status", {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            const badge = document.getElementById("headerAiStatus");
            badge.innerText = data.status;
            if (data.status === "NORMAL") badge.style.color = "var(--status-normal)";
            else if (data.status === "SUSPICIOUS") badge.style.color = "var(--status-suspicious)";
            else badge.style.color = "var(--status-threat)";
        }
    } catch (err) {
        console.error(err);
    }
}

async function loadThreatStatus() {
    try {
        const res = await fetch("/api/threat-detection/status", {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            document.getElementById("threatGaugeVal").innerText = data.anomaly_score;
            document.getElementById("featFailedLogins").innerText = data.failed_logins;
            document.getElementById("featEncReqs").innerText = data.encryption_requests;
            document.getElementById("featDecReqs").innerText = data.decryption_requests;
            document.getElementById("featFailedDec").innerText = data.failed_decryptions;
            document.getElementById("threatExplanationText").innerText = data.explanation;

            const badge = document.getElementById("threatClassificationBadge");
            if (data.status === "NORMAL") {
                badge.className = "badge-threat badge-low";
                badge.innerText = "🟢 NORMAL BEHAVIOR";
            } else if (data.status === "SUSPICIOUS") {
                badge.className = "badge-threat badge-medium";
                badge.innerText = "🟡 SUSPICIOUS ACTIVITY";
            } else {
                badge.className = "badge-threat badge-high";
                badge.innerText = "🔴 POTENTIAL THREAT DETECTED";
            }
        }
    } catch (err) {
        console.error("Threat status error:", err);
    }
}

async function triggerAttackSimulation(type) {
    try {
        const res = await fetch(`/api/ai/simulate-attack?attack_type=${type}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`Simulation Triggered: ${data.new_status}`, "error");
            loadThreatStatus();
            loadThreatStatusHeader();
        }
    } catch (err) {
        showToast("Error triggering simulation", "error");
    }
}

async function resetAttackSimulation() {
    try {
        const res = await fetch("/api/ai/reset-simulation", {
            method: "POST",
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        if (res.ok) {
            showToast("Reset anomaly counters to baseline", "success");
            loadThreatStatus();
            loadThreatStatusHeader();
        }
    } catch (err) {
        showToast("Error resetting simulation", "error");
    }
}

// Dashboard & Telemetry Charts
async function loadDashboardStats() {
    try {
        const res = await fetch("/api/dashboard/stats");
        const data = await res.json();
        if (res.ok) {
            document.getElementById("statTotalUsers").innerText = data.total_users;
            document.getElementById("statEncryptedFiles").innerText = data.total_files_encrypted;
            document.getElementById("statDecryptedFiles").innerText = data.total_files_decrypted;
            document.getElementById("statNormalActs").innerText = data.normal_activities;
            document.getElementById("statSuspiciousActs").innerText = data.suspicious_activities;
            document.getElementById("statThreatAlerts").innerText = data.threat_alerts;

            renderCharts(data);
        }
    } catch (err) {
        console.error("Dashboard stats error:", err);
    }
}

function renderCharts(data) {
    // Timeline Line Chart
    const ctx1 = document.getElementById("chartActivityTimeline").getContext("2d");
    if (chartTimeline) chartTimeline.destroy();

    const labels = data.activity_over_time.map(item => item.timestamp);
    const scores = data.activity_over_time.map(item => item.score);

    chartTimeline = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'AI Anomaly Score',
                data: scores,
                borderColor: '#00f2fe',
                backgroundColor: 'rgba(0, 242, 254, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
            }
        }
    });

    // Threat Distribution Pie Chart
    const ctx2 = document.getElementById("chartThreatPie").getContext("2d");
    if (chartPie) chartPie.destroy();

    chartPie = new Chart(ctx2, {
        type: 'doughnut',
        data: {
            labels: ['Low / Normal 🟢', 'Medium / Suspicious 🟡', 'High / Threat 🔴'],
            datasets: [{
                data: [
                    data.threat_level_distribution.Low || 1,
                    data.threat_level_distribution.Medium || 0,
                    data.threat_level_distribution.High || 0
                ],
                backgroundColor: ['#00e676', '#ffb300', '#ff1744'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Outfit' } } }
            }
        }
    });
}

// Security Audit Logs Handlers
async function loadSecurityLogs() {
    const search = document.getElementById("logSearchInput").value;
    const threatLevel = document.getElementById("logThreatFilter").value;

    let url = `/api/logs?limit=50`;
    if (threatLevel && threatLevel !== "All") url += `&threat_level=${threatLevel}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    const tbody = document.getElementById("logsTableBody");
    try {
        const res = await fetch(url);
        const logs = await res.json();
        if (res.ok) {
            if (logs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No matching security logs found.</td></tr>`;
                return;
            }
            tbody.innerHTML = logs.map(l => {
                let badgeClass = "badge-low";
                if (l.threat_level === "Medium") badgeClass = "badge-medium";
                if (l.threat_level === "High") badgeClass = "badge-high";

                return `
                    <tr>
                        <td style="font-size: 0.8rem; color: var(--text-muted);">${new Date(l.timestamp).toLocaleString()}</td>
                        <td><strong>${l.username || 'System'}</strong></td>
                        <td>${l.activity_type}</td>
                        <td>${l.status}</td>
                        <td><span class="badge-threat ${badgeClass}">${l.threat_level}</span></td>
                        <td style="font-family: var(--font-mono); font-size: 0.85rem;">${l.anomaly_score}</td>
                        <td style="font-size: 0.8rem; color: var(--text-muted);">${l.details || ''}</td>
                    </tr>
                `;
            }).join('');
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--status-threat);">Error loading security audit logs</td></tr>`;
    }
}

function filterLogs() {
    loadSecurityLogs();
}

// Download User Security & Activity Report (PDF, CSV, HTML)
// Uses direct URL navigation with ?token= query param so the browser's native
// download manager handles the Content-Disposition: attachment response.
// fetch() with Authorization headers cannot trigger native file downloads.
function downloadCurrentUserReport(format = 'pdf') {
    if (!authToken) {
        showToast("Please log in to export your security report.", "error");
        return;
    }

    const url = `/api/reports/user-activity?format=${encodeURIComponent(format)}&token=${encodeURIComponent(authToken)}`;

    if (format === 'html') {
        // HTML report: open in a new tab for printing / saving
        const win = window.open(url, '_blank');
        if (!win) {
            showToast("Pop-up was blocked. Please allow pop-ups to view the report.", "error");
        }
        return;
    }

    // PDF / CSV: create a hidden anchor and click it — browser handles the download
    const a = document.createElement('a');
    a.href = url;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();

    showToast(`Generating ${format.toUpperCase()} report — download will start shortly.`, "success");
}

// Toast Notifications
function showToast(message, type = 'info') {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;

    let icon = '<i class="fa-solid fa-circle-info"></i>';
    if (type === 'success') icon = '<i class="fa-solid fa-circle-check" style="color: var(--status-normal);"></i>';
    if (type === 'error') icon = '<i class="fa-solid fa-circle-exclamation" style="color: var(--status-threat);"></i>';

    toast.innerHTML = `${icon} <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}
