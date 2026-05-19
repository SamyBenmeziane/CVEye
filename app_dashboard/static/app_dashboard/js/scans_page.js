// Application immediate du theme (avant DOMContentLoaded) pour eviter le "flash blanc"
(function () {
    try {
        var savedTheme = localStorage.getItem("cveye.theme");
        if (savedTheme === "dark") {
            document.documentElement.classList.add("dark");
        }
    } catch (e) {
        // localStorage indisponible : on ignore
    }
})();

document.addEventListener("DOMContentLoaded", function () {
    const SIDEBAR_STORAGE_KEY = "cveye.sidebar.open";
    const FILTER_SCROLL_STORAGE_KEY = "cveye.filterScrollState";
    const SCAN_PROGRESS_MESSAGES = [
        "Scan en cours...",
        "Patientez, vous y etes presque...",
        "Encore un instant, c'est bientot termine...",
    ];
    const scanToastMessageTimers = new Map();
    let scanOverlayFrameId = null;
    const modal = document.getElementById("scanDetailsModal");
    const closeBtn = document.getElementById("closeDetailsBtn");
    const appLayout = document.getElementById("appLayout");
    const sidebarToggles = document.querySelectorAll("[data-sidebar-toggle]");
    const detailTriggers = document.querySelectorAll(".scan-details-trigger");
    const launchScanForms = document.querySelectorAll(".launch-scan-form");
    const profileMenuToggle = document.getElementById("profileMenuToggle");
    const profileMenu = document.getElementById("profileMenu");
    const liveScanToastStack = document.getElementById("liveScanToastStack");
    const loadingForms = document.querySelectorAll("form");
    const scanDetailsTarget = document.getElementById("scanDetailsTarget");
    const scanDetailsStatus = document.getElementById("scanDetailsStatus");
    const scanDetailsPorts = document.getElementById("scanDetailsPorts");
    const scanDetailsVulns = document.getElementById("scanDetailsVulns");
    const scanDetailsTableBody = document.getElementById("scanDetailsTableBody");
    const scanSeverityToolbar = document.getElementById("scanSeverityToolbar");
    const scanSeveritySummary = document.getElementById("scanSeveritySummary");
    const scanSeverityNav = document.getElementById("scanSeverityNav");
    const severityPrevBtn = document.getElementById("severityPrevBtn");
    const severityNextBtn = document.getElementById("severityNextBtn");
    const severityNavLabel = document.getElementById("severityNavLabel");
    const mobileQuery = window.matchMedia("(max-width: 980px)");
   const trackedScanIds = new Set();
const pendingRedirectUrls = new Map();
let scanPollingTimerId = null;
let currentOverlayScanId = null;
let activeSeverityFilter = "";
let severityNavigationItems = [];
let severityNavigationIndex = 0;

    function saveFilterScrollState() {
        try {
            window.sessionStorage.setItem(
                FILTER_SCROLL_STORAGE_KEY,
                JSON.stringify({
                    path: window.location.pathname,
                    scrollY: window.scrollY || window.pageYOffset || 0,
                })
            );
        } catch (error) {
            // sessionStorage indisponible : on ignore
        }
    }

    function restoreFilterScrollState() {
        try {
            const rawState = window.sessionStorage.getItem(FILTER_SCROLL_STORAGE_KEY);
            if (!rawState) {
                return;
            }

            const state = JSON.parse(rawState);
            window.sessionStorage.removeItem(FILTER_SCROLL_STORAGE_KEY);

            if (!state || state.path !== window.location.pathname) {
                return;
            }

            window.requestAnimationFrame(function () {
                window.scrollTo({
                    top: Number(state.scrollY) || 0,
                    behavior: "auto",
                });
            });
        } catch (error) {
            // sessionStorage indisponible : on ignore
        }
    }

    function isSamePathUrl(urlValue) {
        try {
            const targetUrl = new URL(urlValue || window.location.href, window.location.href);
            return targetUrl.pathname === window.location.pathname;
        } catch (error) {
            return false;
        }
    }

    restoreFilterScrollState();

    function getOrCreateGlobalLoadingOverlay() {
        let overlay = document.getElementById("globalLoadingOverlay");
        if (overlay) {
            return overlay;
        }

        overlay = document.createElement("div");
        overlay.id = "globalLoadingOverlay";
        overlay.className = "global-loading-overlay";
        overlay.setAttribute("aria-hidden", "true");
        overlay.innerHTML =
            '<div class="global-loading-card" role="status" aria-live="polite">' +
                '<div class="global-loading-spinner" aria-hidden="true"></div>' +
                '<p class="global-loading-text">Traitement en cours...</p>' +
            "</div>";

        document.body.appendChild(overlay);
        return overlay;
    }

    function showGlobalLoadingOverlay(message) {
        const overlay = getOrCreateGlobalLoadingOverlay();
        const textNode = overlay.querySelector(".global-loading-text");
        if (textNode) {
            textNode.textContent = message || "Traitement en cours...";
        }
        overlay.classList.add("is-visible");
        overlay.setAttribute("aria-hidden", "false");
    }

    function shouldShowGlobalLoadingForForm(form) {
        if (!form) {
            return false;
        }

        const method = (form.getAttribute("method") || "get").toLowerCase();
        const action = form.getAttribute("action") || "";

        if (method !== "post") {
            return false;
        }

        if (form.classList.contains("launch-scan-form")) {
            return false;
        }

        if (form.dataset.skipLoading === "true") {
            return false;
        }

        if (action.endsWith("report.pdf")) {
            return false;
        }

        return true;
    }

    loadingForms.forEach(function (form) {
        form.addEventListener("submit", function () {
            const method = (form.getAttribute("method") || "get").toLowerCase();
            const action = form.getAttribute("action") || window.location.href;
            if (method === "get" && isSamePathUrl(action)) {
                saveFilterScrollState();
            } else if (method === "post") {
                saveFilterScrollState();
            }

            if (!shouldShowGlobalLoadingForForm(form)) {
                return;
            }

            const button = document.activeElement;
            const message = button && button.dataset.loadingMessage
                ? button.dataset.loadingMessage
                : "Traitement en cours...";
            showGlobalLoadingOverlay(message);
        });
    });

    document.querySelectorAll("a.quick-filter-chip[href], a.metric-card-link[href], a.details-btn[href]").forEach(function (link) {
        link.addEventListener("click", function () {
            if (isSamePathUrl(link.href)) {
                saveFilterScrollState();
            }
        });
    });

    function isSidebarOpen() {
        return appLayout && appLayout.classList.contains("sidebar-open");
    }

    function readSidebarState() {
        try {
            const rawValue = window.localStorage.getItem(SIDEBAR_STORAGE_KEY);
            if (rawValue === "true") {
                return true;
            }
            if (rawValue === "false") {
                return false;
            }
        } catch (error) {
            return null;
        }

        return null;
    }

    function persistSidebarState(open) {
        try {
            window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(open));
        } catch (error) {
            // localStorage can be unavailable; keep the interface usable without persistence.
        }
    }

    function syncSidebarRailTooltips() {
        document.querySelectorAll(".sidebar .nav-link").forEach(function (link) {
            const label = link.querySelector(".nav-label");
            const tooltip = label && label.textContent ? label.textContent.trim() : "";
            if (tooltip) {
                link.setAttribute("data-tooltip", tooltip);
            }
        });

        const brand = document.querySelector(".sidebar .brand");
        if (brand) {
            brand.setAttribute("data-tooltip", "CVEye");
        }

        if (profileMenuToggle) {
            const userName = profileMenuToggle.querySelector(".user-name");
            const tooltip = userName && userName.textContent
                ? userName.textContent.trim()
                : "Compte";
            profileMenuToggle.setAttribute("data-tooltip", tooltip);
        }
    }

    function syncBodyOverflow() {
        const modalOpen = modal && modal.classList.contains("show");
        if (modalOpen || (mobileQuery.matches && isSidebarOpen())) {
            document.body.style.overflow = "hidden";
        } else {
            document.body.style.overflow = "";
        }
    }

    function setSidebarState(open) {
        if (!appLayout) {
            return;
        }

        appLayout.classList.toggle("sidebar-open", open);
        appLayout.classList.toggle("sidebar-closed", !open);

        sidebarToggles.forEach(function (toggle) {
            toggle.setAttribute("aria-expanded", String(open));
        });

        persistSidebarState(open);
        syncBodyOverflow();
    }

    if (appLayout) {
        setSidebarState(!mobileQuery.matches);
    }

    syncSidebarRailTooltips();

    if (profileMenuToggle && profileMenu) {
        profileMenuToggle.addEventListener("click", function (event) {
            event.stopPropagation();
            const isOpen = profileMenu.classList.toggle("profile-menu-open");
            profileMenuToggle.setAttribute("aria-expanded", String(isOpen));
        });

        document.addEventListener("click", function (event) {
            if (!profileMenu.contains(event.target) && !profileMenuToggle.contains(event.target)) {
                profileMenu.classList.remove("profile-menu-open");
                profileMenuToggle.setAttribute("aria-expanded", "false");
            }
        });
    }

    if (modal && modal.dataset.autoOpen === "true") {
        syncBodyOverflow();
        const selectedTrigger = modal.dataset.selectedScanId
            ? document.querySelector('.scan-details-trigger[data-scan-id="' + modal.dataset.selectedScanId + '"]')
            : null;
        if (selectedTrigger) {
            window.setTimeout(function () {
                selectedTrigger.click();
            }, 0);
        }
    }

    if (appLayout && !document.querySelector(".sidebar-backdrop")) {
        var backdrop = document.createElement("div");
        backdrop.className = "sidebar-backdrop";
        backdrop.setAttribute("aria-hidden", "true");
        backdrop.addEventListener("click", function () {
            setSidebarState(false);
        });
        document.body.appendChild(backdrop);
    }

    // === Toggle mode sombre / clair ===
    if (!document.querySelector(".theme-toggle")) {
        var themeToggle = document.createElement("button");
        themeToggle.type = "button";
        themeToggle.className = "theme-toggle";
        themeToggle.setAttribute("aria-label", "Basculer entre mode clair et mode sombre");
        themeToggle.innerHTML =
            '<span class="icon-moon" aria-hidden="true">🌙</span>' +
            '<span class="icon-sun" aria-hidden="true">☀️</span>';

        themeToggle.addEventListener("click", function () {
            var isDark = document.documentElement.classList.toggle("dark");
            try {
                localStorage.setItem("cveye.theme", isDark ? "dark" : "light");
            } catch (e) {
                // localStorage indisponible : on ignore
            }
        });

        document.body.appendChild(themeToggle);
    }

    sidebarToggles.forEach(function (toggle) {
        toggle.addEventListener("click", function () {
            setSidebarState(!isSidebarOpen());
        });
    });

    mobileQuery.addEventListener("change", function () {
        syncBodyOverflow();
    });

    function renderStatusBadge(status) {
        if (status === "complete") {
            return '<div class="status-badge completed">Complété</div>';
        }
        if (status === "echoue") {
            return '<div class="status-badge failed">Échoué</div>';
        }
        return '<div class="status-badge neutral">' + status + "</div>";
    }

    function renderInlineStatusBadge(status, scanId) {
        if (status === "complete") {
            return '<span class="status-badge completed" data-scan-status="' + scanId + '">Complété</span>';
        }
        if (status === "echoue") {
            return '<span class="status-badge failed" data-scan-status="' + scanId + '">Échoué</span>';
        }
        return '<span class="status-badge neutral" data-scan-status="' + scanId + '">' + escapeHtml(status) + "</span>";
    }

    function formatProgressLabel(current, total, percent) {
    return current + " / " + total + " ports (" + percent + "%)";
}

function formatDurationLabel(seconds) {
    const safeSeconds = Number.isFinite(seconds) ? seconds : 0;
    return safeSeconds + " s";
}

function getProgressMessageFromScanData(data) {
    if (data.finished && data.status === "complete") {
        return "Scan termine. Redirection vers les resultats...";
    }

    if (data.finished && data.status === "echoue") {
        return "Le scan a echoue.";
    }

    if (data.ports_scanned_total > 0 && data.ports_scanned_current >= data.ports_scanned_total) {
        return "Analyse des services et des vulnerabilites...";
    }

    if (data.progress_percent >= 70) {
        return SCAN_PROGRESS_MESSAGES[2];
    }

    if (data.progress_percent >= 30) {
        return SCAN_PROGRESS_MESSAGES[1];
    }

    return SCAN_PROGRESS_MESSAGES[0];
}


    function escapeHtml(value) {
        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    function getCsrfToken() {
        const csrfInput = document.querySelector("input[name='csrfmiddlewaretoken']");
        return csrfInput ? csrfInput.value : "";
    }
    /**
     * crÃ©ation/rÃ©cupÃ©ration du toast
     * @param {*} scanId 
     * @returns 
     */
    function getOrCreateToast(scanId) {
        if (!liveScanToastStack) {
            return null;
        }
        //eviter de crÃ©er un nouveau toast si un toast existe dÃ©jÃ  pour ce scanId (ex: en cas de lancement rapide d'analyse sur la mÃªme cible)
        let toast = liveScanToastStack.querySelector('[data-scan-toast-id="' + scanId + '"]');
        if (toast) {
            return toast;
        }

        toast = document.createElement("div");
        toast.className = "alert toast toast-progress";
        toast.setAttribute("data-scan-toast-id", scanId);
        liveScanToastStack.appendChild(toast);
        return toast;
    }

    function getOrCreateScanOverlay() {
    let overlay = document.getElementById("scanLaunchOverlay");
    if (overlay) {
        return overlay;
    }

    overlay = document.createElement("div");
    overlay.id = "scanLaunchOverlay";
    overlay.className = "scan-launch-overlay";
    overlay.setAttribute("aria-hidden", "true");
    overlay.innerHTML =
        '<div class="scan-launch-backdrop"></div>' +
        '<div class="scan-launch-shell">' +
            '<div class="scan-launch-grid"></div>' +
            '<div class="scan-launch-radar">' +
                '<div class="scan-launch-radar-ring ring-one"></div>' +
                '<div class="scan-launch-radar-ring ring-two"></div>' +
                '<div class="scan-launch-radar-ring ring-three"></div>' +
                '<div class="scan-launch-radar-sweep"></div>' +
                '<div class="scan-launch-radar-core"></div>' +
            "</div>" +
            '<div class="scan-launch-panel">' +
                '<div class="scan-launch-kicker">Cyber scan</div>' +
                '<h2 class="scan-launch-title">Initialisation de l analyse</h2>' +
                '<div class="scan-launch-target" data-scan-overlay-target>Preparation...</div>' +
                '<div class="scan-launch-copy" data-scan-overlay-copy>' + SCAN_PROGRESS_MESSAGES[0] + "</div>" +
                '<div class="scan-launch-copy" data-scan-overlay-counter>0 / 65535 ports (0%)</div>' +
                '<div class="scan-launch-copy" data-scan-overlay-duration>Durée: 0 s</div>' +
                '<div class="scan-launch-progress">' +
                    '<span class="scan-launch-progress-bar" data-scan-overlay-bar></span>' +
                "</div>" +
                '<div class="scan-launch-meta">' +
                    '<span>Enumeration reseau</span>' +
                    '<span>Fingerprint services</span>' +
                    '<span>Verification active</span>' +
                "</div>" +
            "</div>" +
        "</div>";

    document.body.appendChild(overlay);
    return overlay;
}

    function setOverlayMessage(overlay, elapsedMs) {
        const copyNode = overlay.querySelector("[data-scan-overlay-copy]");
        const barNode = overlay.querySelector("[data-scan-overlay-bar]");
        if (copyNode) {
            copyNode.textContent = getProgressMessage(elapsedMs);
        }
        if (barNode) {
            const progress = Math.min(94, 10 + Math.round(elapsedMs / 160));
            barNode.style.width = progress + "%";
        }
    }

    

    function clearScanOverlayLoop() {
    if (scanOverlayFrameId) {
        window.cancelAnimationFrame(scanOverlayFrameId);
        scanOverlayFrameId = null;
    }
}

function hideScanOverlay() {
    const overlay = document.getElementById("scanLaunchOverlay");
    if (!overlay) {
        return;
    }

    clearScanOverlayLoop();
    currentOverlayScanId = null;
    overlay.classList.remove("is-visible");
    overlay.setAttribute("aria-hidden", "true");
}

function showScanOverlay(payload) {
    const overlay = getOrCreateScanOverlay();
    const targetNode = overlay.querySelector("[data-scan-overlay-target]");
    const copyNode = overlay.querySelector("[data-scan-overlay-copy]");
    const counterNode = overlay.querySelector("[data-scan-overlay-counter]");
    const durationNode = overlay.querySelector("[data-scan-overlay-duration]");
    const barNode = overlay.querySelector("[data-scan-overlay-bar]");

    currentOverlayScanId = payload.scanId || null;

    if (targetNode) {
        targetNode.textContent = payload.targetLabel || "Analyse du serveur en cours";
    }

    if (copyNode) {
        copyNode.textContent = SCAN_PROGRESS_MESSAGES[0];
    }

    if (counterNode) {
        counterNode.textContent = "0 / 65535 ports (0%)";
    }

    if (durationNode) {
        durationNode.textContent = "Durée: 0 s";
    }

    if (barNode) {
        barNode.style.width = "0%";
    }

    overlay.classList.add("is-visible");
    overlay.setAttribute("aria-hidden", "false");
}

function updateScanOverlay(data) {
    const overlay = document.getElementById("scanLaunchOverlay");
    if (!overlay || currentOverlayScanId !== data.id) {
        return;
    }

    const targetNode = overlay.querySelector("[data-scan-overlay-target]");
    const copyNode = overlay.querySelector("[data-scan-overlay-copy]");
    const counterNode = overlay.querySelector("[data-scan-overlay-counter]");
    const durationNode = overlay.querySelector("[data-scan-overlay-duration]");
    const barNode = overlay.querySelector("[data-scan-overlay-bar]");

    if (targetNode) {
        targetNode.textContent = "Analyse de " + data.target_address;
    }

    if (copyNode) {
        copyNode.textContent = getProgressMessageFromScanData(data);
    }

    if (counterNode) {
        counterNode.textContent = formatProgressLabel(
            data.ports_scanned_current,
            data.ports_scanned_total,
            data.progress_percent
        );
    }

    if (durationNode) {
        durationNode.textContent = "Durée: " + formatDurationLabel(data.duration_seconds);
    }

    if (barNode) {
        barNode.style.width = Math.max(0, Math.min(100, data.progress_percent)) + "%";
    }
}

    function clearToastMessageTimer(scanId) {
        const timerId = scanToastMessageTimers.get(scanId);
        if (!timerId) {
            return;
        }

        window.clearInterval(timerId);
        scanToastMessageTimers.delete(scanId);
    }
    //choisir le message en fonction des secondes Ã©coulÃ©es
    function getProgressMessage(elapsedMs) {
        if (elapsedMs >= 10000) {
            return SCAN_PROGRESS_MESSAGES[2];
        }
        if (elapsedMs >= 5000) {
            return SCAN_PROGRESS_MESSAGES[1];
        }
        return SCAN_PROGRESS_MESSAGES[0];
    }

    function startToastMessageRotation(toast, scanId) {
        const messageNode = toast.querySelector(".toast-progress-copy");
        if (!messageNode) {
            return;
        }

        clearToastMessageTimer(scanId);

        const startedAt = Date.now();
        const updateMessage = function () {
            messageNode.textContent = getProgressMessage(Date.now() - startedAt);
        };

        updateMessage();
        scanToastMessageTimers.set(scanId, window.setInterval(updateMessage, 1000));
    }

    function getScanTargetLabel(form) {
        if (form && form.dataset.scanLabel) {
            return form.dataset.scanLabel;
        }

        const tableRow = form.closest("tr");
        if (tableRow) {
            const targetName = tableRow.querySelector(".target-name");
            if (targetName && targetName.textContent.trim()) {
                return "Analyse de " + targetName.textContent.trim();
            }
        }

        return "Analyse du serveur en cours";
    }

    async function handleLaunchScanFormSubmit(form, event) {
        event.preventDefault();
        const scanTargetLabel = getScanTargetLabel(form);

        const submitButton = form.querySelector(".launch-scan-btn, .port-rescan-btn");
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.classList.add("launch-scan-btn-loading");
            submitButton.setAttribute("aria-busy", "true");
        }

        try {
            showScanOverlay({
                targetLabel: scanTargetLabel,
                scanId: null,
            });

            const response = await fetch(form.action, {
                method: "POST",
                headers: {
                    "X-Requested-With": "XMLHttpRequest",
                    "X-CSRFToken": getCsrfToken(),
                },
                credentials: "same-origin",
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Impossible de lancer le scan.");
            }

            currentOverlayScanId = data.id;
            trackedScanIds.add(data.id);
            pendingRedirectUrls.set(data.id, data.redirect_url);

            startScanPolling();
            pollTrackedScans();
        } catch (error) {
            hideScanOverlay();

            const fallbackToast = getOrCreateToast("launch-error-" + Math.random().toString(16).slice(2));
            if (fallbackToast) {
                fallbackToast.className = "alert toast toast-progress error";
                fallbackToast.textContent = error.message;
            }
        } finally {
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.classList.remove("launch-scan-btn-loading");
                submitButton.removeAttribute("aria-busy");
            }
        }
    }
    function renderScanToast(data) {
    const overlay = document.getElementById("scanLaunchOverlay");
    const overlayVisible = overlay && overlay.classList.contains("is-visible");

    if (overlayVisible && currentOverlayScanId === data.id) {
        return;
    }

    const toast = getOrCreateToast(data.id);
    if (!toast) {
        return;
    }

    const statusClass = data.status === "echoue"
        ? "error"
        : data.finished
            ? "success"
            : "info";

    toast.className = "alert toast toast-progress " + statusClass;
    toast.innerHTML =
        '<div class="toast-progress-head">' +
            '<div class="toast-progress-title">' +
                (data.finished ? "" : '<span class="loading-spinner" aria-hidden="true"></span>') +
                '<strong>Scan ' + escapeHtml(data.target_address) + "</strong>" +
            "</div>" +
            '<span>' + escapeHtml(data.status) + "</span>" +
        "</div>" +
        '<div class="toast-progress-copy">' + escapeHtml(getProgressMessageFromScanData(data)) + "</div>" +
        '<div class="toast-progress-copy">Progression: ' +
            escapeHtml(formatProgressLabel(data.ports_scanned_current, data.ports_scanned_total, data.progress_percent)) +
        "</div>" +
        '<div class="toast-progress-copy">Durée: ' + escapeHtml(formatDurationLabel(data.duration_seconds)) + "</div>" +
        '<div class="toast-progress-copy">Ports ouverts: ' + escapeHtml(data.ports_open) + "</div>" +
        (data.error_message ? '<div class="toast-progress-copy toast-progress-error">' + escapeHtml(data.error_message) + "</div>" : "");

    if (data.finished) {
        clearToastMessageTimer(data.id);
        window.setTimeout(function () {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 7000);
    } else {
        startToastMessageRotation(toast, data.id);
    }
}
    function updateScanRow(data) {
    const rowNode = document.querySelector('[data-scan-row-id="' + data.id + '"]');
    if (rowNode) {
        if (data.finished) {
            rowNode.removeAttribute("data-scan-active");
        } else {
            rowNode.setAttribute("data-scan-active", "true");
        }
    }

    const statusNode = document.querySelector('[data-scan-status="' + data.id + '"]');
    if (statusNode) {
        statusNode.outerHTML = renderInlineStatusBadge(data.status, data.id);
    }

    const openPortsNode = document.querySelector('[data-scan-open-ports="' + data.id + '"]');
    if (openPortsNode) {
        openPortsNode.textContent = data.ports_open;
    }

    const progressNode = document.querySelector('[data-scan-progress="' + data.id + '"] .progress-inline');
    if (progressNode) {
        progressNode.textContent = formatProgressLabel(
            data.ports_scanned_current,
            data.ports_scanned_total,
            data.progress_percent
        );
    }

    const durationNode = document.querySelector('[data-scan-duration="' + data.id + '"]');
    if (durationNode) {
        durationNode.textContent = formatDurationLabel(data.duration_seconds);
    }

    if (modal && modal.dataset.selectedScanId === data.id) {
        if (scanDetailsStatus) {
            scanDetailsStatus.innerHTML = renderStatusBadge(data.status);
        }
        if (scanDetailsPorts) {
            scanDetailsPorts.textContent = data.ports_open;
        }
        if (scanDetailsVulns && typeof data.vulnerability_count !== "undefined") {
            scanDetailsVulns.textContent = data.vulnerability_count;
        }
    }
}

async function pollTrackedScans() {
    if (!trackedScanIds.size) {
        if (scanPollingTimerId) {
            window.clearInterval(scanPollingTimerId);
            scanPollingTimerId = null;
        }
        return;
    }

    try {
        const idsParam = encodeURIComponent(Array.from(trackedScanIds).join(","));
        const response = await fetch("/scans/progress/?ids=" + idsParam, {
            headers: { "X-Requested-With": "XMLHttpRequest" },
            credentials: "same-origin",
            cache: "no-store",
        });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Impossible de recuperer la progression du scan.");
        }

        let redirectUrl = null;

        (data.scans || []).forEach(function (scanData) {
            updateScanOverlay(scanData);
            renderScanToast(scanData);
            updateScanRow(scanData);

            if (scanData.finished) {
                trackedScanIds.delete(scanData.id);

                if (scanData.status === "complete" && pendingRedirectUrls.has(scanData.id)) {
                    redirectUrl = pendingRedirectUrls.get(scanData.id);
                    pendingRedirectUrls.delete(scanData.id);
                }

                if (scanData.status === "echoue" && currentOverlayScanId === scanData.id) {
                    window.setTimeout(function () {
                        hideScanOverlay();
                    }, 1200);
                }
            }
        });

        if (!trackedScanIds.size && scanPollingTimerId) {
            window.clearInterval(scanPollingTimerId);
            scanPollingTimerId = null;
        }

        if (redirectUrl) {
            window.setTimeout(function () {
                window.location.href = redirectUrl;
            }, 700);
        }
    } catch (error) {
        console.error(error);
    }
}

function startScanPolling() {
    if (!trackedScanIds.size || scanPollingTimerId) {
        return;
    }

    pollTrackedScans();
    scanPollingTimerId = window.setInterval(pollTrackedScans, 1000);
}


    function buildSeverityChip(label, count, mode) {
        const normalizedClass = label === "Critique"
            ? "severity-critique"
            : label === "Élevée"
                ? "severity-elevee"
                : label === "Moyenne"
                    ? "severity-moyenne"
                    : "severity-faible";
        const zeroClass = Number(count) === 0 ? " severity-chip-zero" : "";

        if (mode === "filter") {
            return "<button type=\"button\" class=\"severity-chip " + normalizedClass + zeroClass + "\" data-severity-filter=\"" + escapeHtml(label) + "\">" + escapeHtml(label) + " " + escapeHtml(count) + "</button>";
        }

        return "<span class=\"severity-chip " + normalizedClass + zeroClass + "\" data-item-severity=\"" + escapeHtml(label) + "\">" + escapeHtml(label) + " " + escapeHtml(count) + "</span>";
    }

    function openAccordionItem(itemNode) {
        if (!scanDetailsTableBody || !itemNode) {
            return;
        }

        scanDetailsTableBody.querySelectorAll(".scan-accordion-item").forEach(function (node) {
            const shouldOpen = node === itemNode;
            node.classList.toggle("is-open", shouldOpen);
            const body = node.querySelector(".scan-accordion-body");
            const trigger = node.querySelector(".scan-accordion-trigger");
            if (body) {
                body.hidden = !shouldOpen;
            }
            if (trigger) {
                trigger.setAttribute("aria-expanded", String(shouldOpen));
            }
        });
    }

    function updateSeverityNavigationLabel() {
        if (!severityNavLabel) {
            return;
        }
        if (!severityNavigationItems.length) {
            severityNavLabel.textContent = "0 / 0";
            return;
        }
        severityNavLabel.textContent = (severityNavigationIndex + 1) + " / " + severityNavigationItems.length;
    }

    function refreshSeverityNavigation() {
        if (!scanSeverityNav) {
            return;
        }
        const visibleItems = Array.from(scanDetailsTableBody.querySelectorAll(".scan-accordion-item"))
            .filter(function (node) {
                return !node.hidden && node.dataset.matchesSeverity === "true";
            });

        severityNavigationItems = visibleItems;
        severityNavigationIndex = 0;

        const showNav = Boolean(activeSeverityFilter) && severityNavigationItems.length > 1;
        scanSeverityNav.hidden = !showNav;

        if (severityNavigationItems.length) {
            openAccordionItem(severityNavigationItems[0]);
        }

        updateSeverityNavigationLabel();
    }

    function applySeverityFilter(filterLabel) {
        activeSeverityFilter = filterLabel || "";

        if (!scanDetailsTableBody) {
            return;
        }

        scanDetailsTableBody.querySelectorAll(".scan-accordion-item").forEach(function (node) {
            const matches = !activeSeverityFilter || node.dataset.severities.includes(activeSeverityFilter);
            node.hidden = !matches;
            node.dataset.matchesSeverity = matches ? "true" : "false";
        });

        if (scanSeveritySummary) {
            scanSeveritySummary.querySelectorAll("[data-severity-filter]").forEach(function (chip) {
                chip.classList.toggle("is-active", chip.dataset.severityFilter === activeSeverityFilter);
            });
        }

        refreshSeverityNavigation();
    }

    function renderSeveritySummary(details) {
        if (!scanSeverityToolbar || !scanSeveritySummary) {
            return;
        }

        if (!details.length) {
            scanSeverityToolbar.hidden = true;
            return;
        }

        const totals = {
            "Critique": 0,
            "Élevée": 0,
            "Moyenne": 0,
            "Faible": 0,
        };

        details.forEach(function (item) {
            totals["Critique"] += item.severity_counts.Critique || 0;
            totals["Élevée"] += item.severity_counts["Élevée"] || 0;
            totals["Moyenne"] += item.severity_counts.Moyenne || 0;
            totals["Faible"] += item.severity_counts.Faible || 0;
        });

        scanSeveritySummary.innerHTML =
            buildSeverityChip("Critique", totals["Critique"], "filter") +
            buildSeverityChip("Élevée", totals["Élevée"], "filter") +
            buildSeverityChip("Moyenne", totals["Moyenne"], "filter") +
            buildSeverityChip("Faible", totals["Faible"], "filter");
        scanSeverityToolbar.hidden = false;
    }

    function renderDetailsRows(details, targetId) {
        if (!details.length) {
            if (scanSeverityToolbar) {
                scanSeverityToolbar.hidden = true;
            }
            return '<div class="empty-row">Aucun port ouvert à afficher.</div>';
        }

        renderSeveritySummary(details);

        var MAX_CVE_VISIBLE = 5;
        var MAX_BANNER_CHARS = 140;

        return details.map(function (item) {
            var allVulns = item.vulnerabilities || [];
            var hasMoreVulns = allVulns.length > MAX_CVE_VISIBLE;
            var visibleVulns = hasMoreVulns ? allVulns.slice(0, MAX_CVE_VISIBLE) : allVulns;
            var hiddenVulns = hasMoreVulns ? allVulns.slice(MAX_CVE_VISIBLE) : [];

            var vulnRows = visibleVulns.map(function (vuln) {
                return "<div>" + escapeHtml(vuln.cve_id) + (vuln.severity ? " — " + escapeHtml(vuln.severity) : "") + "</div>";
            }).join("");

            var hiddenVulnRows = hiddenVulns.map(function (vuln) {
                return "<div class=\"detail-extra\" hidden>" + escapeHtml(vuln.cve_id) + (vuln.severity ? " — " + escapeHtml(vuln.severity) : "") + "</div>";
            }).join("");

            var vulnShowMore = hasMoreVulns
                ? "<button type=\"button\" class=\"scan-detail-show-more\">Voir plus (" + (allVulns.length - MAX_CVE_VISIBLE) + ")</button>"
                : "";

            var vulnLink = targetId
                ? "<div><a class=\"scan-detail-more-link\" href=\"/vulnerabilities/?target=" + encodeURIComponent(targetId) + "\">Voir toutes les vulnérabilités</a></div>"
                : "";

            var vulnerabilityBlock = allVulns.length
                ? "<div class=\"scan-detail-list\">" + vulnRows + hiddenVulnRows + vulnShowMore + vulnLink + "</div>"
                : "<div class=\"scan-detail-list\"><div>Aucune CVE</div></div>";

            var headers = Object.entries(item.headers_without_server || {});
            var MAX_HEADERS = 4;
            var hasMoreHeaders = headers.length > MAX_HEADERS;
            var visibleHeaders = hasMoreHeaders ? headers.slice(0, MAX_HEADERS) : headers;
            var hiddenHeaders = hasMoreHeaders ? headers.slice(MAX_HEADERS) : [];

            var headerRows = visibleHeaders.map(function (entry) {
                return "<div>" + escapeHtml(entry[0]) + " : " + escapeHtml(entry[1]) + "</div>";
            }).join("");

            var hiddenHeaderRows = hiddenHeaders.map(function (entry) {
                return "<div class=\"detail-extra\" hidden>" + escapeHtml(entry[0]) + " : " + escapeHtml(entry[1]) + "</div>";
            }).join("");

            var headersShowMore = hasMoreHeaders
                ? "<button type=\"button\" class=\"scan-detail-show-more\">Voir plus (" + (headers.length - MAX_HEADERS) + ")</button>"
                : "";

            var headersBlock = headers.length
                ? "<div class=\"scan-detail-item\"><span class=\"autres-label\">En-têtes</span><div class=\"scan-detail-list\">" + headerRows + hiddenHeaderRows + headersShowMore + "</div></div>"
                : "";

            var bannerBlock = "";
            if (item.banner) {
                var truncated = item.banner.length > MAX_BANNER_CHARS;
                var visibleBanner = escapeHtml(truncated ? item.banner.slice(0, MAX_BANNER_CHARS) : item.banner);
                var hiddenBanner = truncated
                    ? "<span class=\"detail-extra\" hidden>" + escapeHtml(item.banner.slice(MAX_BANNER_CHARS)) + "</span>"
                    : "";
                var bannerShowMore = truncated
                    ? "<button type=\"button\" class=\"scan-detail-show-more\">Voir plus</button>"
                    : "";
                bannerBlock = "<div class=\"scan-detail-item\"><span class=\"autres-label\">Bannière</span>"
                    + "<div class=\"scan-detail-list\"><div>" + visibleBanner + (truncated ? "…" : "") + hiddenBanner + "</div>"
                    + bannerShowMore + "</div></div>";
            }

            const productLabel = item.product
                ? escapeHtml(item.product + (item.version ? " " + item.version : ""))
                : "N/A";

            const severities = Object.keys(item.severity_counts || {}).filter(function (label) {
                return (item.severity_counts[label] || 0) > 0;
            });

            var dominantSeverity = item.dominant_severity || "Inconnue";

            var serviceLabel = item.service || "unknown";
            serviceLabel = serviceLabel.charAt(0).toUpperCase() + serviceLabel.slice(1);

            var metaService = "<div class=\"scan-meta-badge\"><span class=\"scan-meta-label\">Service</span><span class=\"scan-meta-val\">" + escapeHtml(serviceLabel) + "</span></div>";
            var metaProduct = item.product ? "<div class=\"scan-meta-badge\"><span class=\"scan-meta-label\">Produit</span><span class=\"scan-meta-val\">" + escapeHtml(item.product) + "</span></div>" : "";
            var metaVersion = "<div class=\"scan-meta-badge\"><span class=\"scan-meta-label\">Version</span><span class=\"scan-meta-val\">" + escapeHtml(item.display_version) + "</span></div>";
            var metaStatut = "<div class=\"scan-meta-badge\"><span class=\"scan-meta-label\">Statut</span><span class=\"scan-meta-val scan-meta-open\">Ouvert</span></div>";

            var rescanAction = targetId
                ? "/targets/" + encodeURIComponent(targetId) + "/scan/ports/" + encodeURIComponent(item.port) + "/async/"
                : "";
            var rescanButton = targetId
                ? "<form method=\"post\" action=\"" + rescanAction + "\" class=\"launch-scan-form port-rescan-form\" data-scan-label=\"Revérification du port " + escapeHtml(String(item.port)) + " sur le serveur\">" +
                    "<button type=\"submit\" class=\"port-rescan-btn\" title=\"Revérifier ce port\" aria-label=\"Revérifier le port " + escapeHtml(String(item.port)) + "\">↻</button>" +
                "</form>"
                : "";

            return "<article class=\"scan-accordion-item\" data-severities=\"" + escapeHtml(severities.join("|")) + "\" data-matches-severity=\"true\" data-dominant=\"" + escapeHtml(dominantSeverity) + "\">" +
                "<div class=\"scan-accordion-head\">" +
                    "<button type=\"button\" class=\"scan-accordion-trigger\" aria-expanded=\"false\">" +
                        "<span class=\"scan-accordion-main\">" +
                            "<span class=\"scan-accordion-port\">" + escapeHtml(item.port) + "/" + escapeHtml(item.protocol || "TCP") + "</span>" +
                            "<span class=\"scan-accordion-service\">" + escapeHtml(serviceLabel) + "</span>" +
                            "<span class=\"scan-accordion-version\">" + escapeHtml(item.display_version) + "</span>" +
                        "</span>" +
                        "<span class=\"scan-accordion-summary\">" +
                            "<span class=\"scan-accordion-total\">" + escapeHtml(item.total_vulnerabilities || 0) + " CVE</span>" +
                            buildSeverityChip("Critique", item.severity_counts.Critique || 0, "item") +
                            buildSeverityChip("Élevée", item.severity_counts["Élevée"] || 0, "item") +
                            buildSeverityChip("Moyenne", item.severity_counts.Moyenne || 0, "item") +
                            buildSeverityChip("Faible", item.severity_counts.Faible || 0, "item") +
                        "</span>" +
                    "</button>" +
                    rescanButton +
                "</div>" +
                "<div class=\"scan-accordion-body\" hidden>" +
                    "<div class=\"scan-accordion-meta\">" +
                        metaService + metaProduct + metaVersion + metaStatut +
                    "</div>" +
                    "<div class=\"scan-accordion-columns\">" +
                        "<div class=\"scan-accordion-panel\"><p class=\"eyebrow\">Vulnérabilités</p>" + vulnerabilityBlock + "</div>" +
                        "<div class=\"scan-accordion-panel\"><p class=\"eyebrow\">Données techniques</p>" + (bannerBlock || headersBlock ? bannerBlock + headersBlock : "<div class=\"scan-detail-list\"><div>Aucune donnée supplémentaire</div></div>") + "</div>" +
                    "</div>" +
                "</div>" +
            "</article>";
        }).join("");
    }

    async function loadHistoryScanDetails(itemNode) {
        if (!itemNode) {
            return;
        }

        const trigger = itemNode.querySelector(".scan-history-trigger");
        const detailsHost = itemNode.querySelector(".js-history-scan-details");
        const detailsUrl = trigger ? trigger.dataset.detailsUrl : "";
        if (!detailsHost || !detailsUrl) {
            return;
        }

        if (detailsHost.dataset.loaded === "true") {
            return;
        }

        detailsHost.innerHTML = '<div class="scan-row-loading">Chargement des détails du scan...</div>';

        try {
            const response = await fetch(detailsUrl, {
                headers: { "X-Requested-With": "XMLHttpRequest" },
                credentials: "same-origin",
                cache: "no-store",
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Impossible de charger les détails du scan.");
            }

            detailsHost.innerHTML = '<div class="scan-accordion-list">' + renderDetailsRows(data.details || [], data.target_id || "") + '</div>';
            detailsHost.dataset.loaded = "true";
        } catch (error) {
            detailsHost.innerHTML = '<div class="empty-row">' + escapeHtml(error.message) + '</div>';
        }
    }

    document.querySelectorAll('[data-scan-active="true"]').forEach(function (row) {
    if (row.dataset.scanRowId) {
        trackedScanIds.add(row.dataset.scanRowId);
    }
});

startScanPolling();
    detailTriggers.forEach(function (trigger) {
        trigger.addEventListener("click", async function (event) {
            event.preventDefault();

            const detailsUrl = trigger.dataset.detailsUrl;
            if (!detailsUrl || !modal) {
                return;
            }

            detailTriggers.forEach(function (item) {
                item.classList.remove("details-btn-active");
            });
            trigger.classList.add("details-btn-active");

            if (scanDetailsTarget) {
                scanDetailsTarget.textContent = "Chargement...";
            }
            if (scanDetailsStatus) {
                scanDetailsStatus.innerHTML = '<div class="status-badge neutral">Chargement</div>';
            }
            if (scanDetailsPorts) {
                scanDetailsPorts.textContent = "...";
            }
            if (scanDetailsVulns) {
                scanDetailsVulns.textContent = "...";
            }
            if (scanDetailsTableBody) {
                scanDetailsTableBody.innerHTML = '<tr><td colspan="8" class="empty-row">Chargement des détails...</td></tr>';
            }

            modal.classList.add("show");
            syncBodyOverflow();

            try {
                const response = await fetch(detailsUrl, {
                    headers: { "X-Requested-With": "XMLHttpRequest" },
                    credentials: "same-origin",
                    cache: "no-store",
                });
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || "Impossible de charger les details.");
                }

                if (scanDetailsTarget) {
                    scanDetailsTarget.textContent = data.target_address;
                }
                if (scanDetailsStatus) {
                    scanDetailsStatus.innerHTML = renderStatusBadge(data.status);
                }
                if (scanDetailsPorts) {
                    scanDetailsPorts.textContent = data.ports_open;
                }
                if (scanDetailsVulns) {
                    if (data.target_id) {
                        scanDetailsVulns.innerHTML = '<a href="/vulnerabilities/?target=' + encodeURIComponent(data.target_id) + '" class="stat-link">' + escapeHtml(String(data.vulnerability_count)) + '</a>';
                    } else {
                        scanDetailsVulns.textContent = data.vulnerability_count;
                    }
                }
                if (scanDetailsTableBody) {
                    scanDetailsTableBody.innerHTML = renderDetailsRows(data.details || [], data.target_id || "");
                }
                applySeverityFilter("");

                if (modal) {
                    modal.dataset.selectedScanId = data.id;
                }
            } catch (error) {
                if (scanDetailsTarget) {
                    scanDetailsTarget.textContent = "Erreur";
                }
                if (scanDetailsStatus) {
                    scanDetailsStatus.innerHTML = '<div class="status-badge failed">Erreur</div>';
                }
                if (scanDetailsPorts) {
                    scanDetailsPorts.textContent = "0";
                }
                if (scanDetailsVulns) {
                    scanDetailsVulns.textContent = "0";
                }
                if (scanDetailsTableBody) {
                    scanDetailsTableBody.innerHTML = '<tr><td colspan="8" class="empty-row">' + escapeHtml(error.message) + "</td></tr>";
                }
            }
        });
    });

    document.addEventListener("submit", function (event) {
        const form = event.target.closest(".launch-scan-form");
        if (!form) {
            return;
        }

        handleLaunchScanFormSubmit(form, event);
    });

    if (closeBtn && modal) {
        closeBtn.addEventListener("click", function () {
            modal.classList.remove("show");
            syncBodyOverflow();
        });
    }

    if (scanDetailsTableBody) {
        scanDetailsTableBody.addEventListener("click", function (event) {
            const severityButton = event.target.closest("[data-severity-filter]");
            if (severityButton) {
                const nextFilter = severityButton.dataset.severityFilter === activeSeverityFilter
                    ? ""
                    : severityButton.dataset.severityFilter;
                applySeverityFilter(nextFilter);
                return;
            }

            const showMoreBtn = event.target.closest(".scan-detail-show-more");
            if (showMoreBtn) {
                const container = showMoreBtn.parentElement;
                if (container) {
                    container.querySelectorAll(".detail-extra").forEach(function (el) {
                        el.hidden = false;
                    });
                }
                showMoreBtn.remove();
                return;
            }

            const trigger = event.target.closest(".scan-accordion-trigger");
            if (!trigger) {
                return;
            }

            const item = trigger.closest(".scan-accordion-item");
            const isOpen = item && item.classList.contains("is-open");
            if (isOpen) {
                item.classList.remove("is-open");
                const body = item.querySelector(".scan-accordion-body");
                if (body) {
                    body.hidden = true;
                }
                trigger.setAttribute("aria-expanded", "false");
                return;
            }

            openAccordionItem(item);
        });
    }

    if (scanSeveritySummary) {
        scanSeveritySummary.addEventListener("click", function (event) {
            const chip = event.target.closest("[data-severity-filter]");
            if (!chip) {
                return;
            }
            const nextFilter = chip.dataset.severityFilter === activeSeverityFilter ? "" : chip.dataset.severityFilter;
            applySeverityFilter(nextFilter);
        });
    }

    if (severityPrevBtn) {
        severityPrevBtn.addEventListener("click", function () {
            if (!severityNavigationItems.length) {
                return;
            }
            severityNavigationIndex = (severityNavigationIndex - 1 + severityNavigationItems.length) % severityNavigationItems.length;
            openAccordionItem(severityNavigationItems[severityNavigationIndex]);
            updateSeverityNavigationLabel();
        });
    }

    if (severityNextBtn) {
        severityNextBtn.addEventListener("click", function () {
            if (!severityNavigationItems.length) {
                return;
            }
            severityNavigationIndex = (severityNavigationIndex + 1) % severityNavigationItems.length;
            openAccordionItem(severityNavigationItems[severityNavigationIndex]);
            updateSeverityNavigationLabel();
        });
    }

    const selectedScanTrigger = document.getElementById("selectedScanTrigger");
    const selectedScanCard = document.getElementById("selectedScanCard");
    const selectedScanBody = document.getElementById("selectedScanBody");
    if (selectedScanTrigger && selectedScanCard && selectedScanBody) {
        selectedScanTrigger.addEventListener("click", function () {
            const willOpen = !selectedScanCard.classList.contains("is-open");
            selectedScanCard.classList.toggle("is-open", willOpen);
            selectedScanBody.hidden = !willOpen;
            selectedScanTrigger.setAttribute("aria-expanded", String(willOpen));
        });
    }

    document.querySelectorAll(".js-history-scan-details").forEach(function (container) {
        container.addEventListener("click", function (event) {
            const showMoreBtn = event.target.closest(".scan-detail-show-more");
            if (showMoreBtn) {
                const parent = showMoreBtn.parentElement;
                if (parent) {
                    parent.querySelectorAll(".detail-extra").forEach(function (el) {
                        el.hidden = false;
                    });
                }
                showMoreBtn.remove();
                return;
            }

            const trigger = event.target.closest(".scan-accordion-trigger");
            if (!trigger) {
                return;
            }

            const item = trigger.closest(".scan-accordion-item");
            if (!item) {
                return;
            }

            container.querySelectorAll(".scan-accordion-item").forEach(function (node) {
                const shouldOpen = node === item && !node.classList.contains("is-open");
                node.classList.toggle("is-open", shouldOpen);
                const body = node.querySelector(".scan-accordion-body");
                const nodeTrigger = node.querySelector(".scan-accordion-trigger");
                if (body) {
                    body.hidden = !shouldOpen;
                }
                if (nodeTrigger) {
                    nodeTrigger.setAttribute("aria-expanded", String(shouldOpen));
                }
            });
        });
    });

    document.querySelectorAll("#scanHistoryAccordion .scan-history-trigger").forEach(function (trigger) {
        trigger.addEventListener("click", async function () {
            const item = trigger.closest(".scan-history-item");
            const body = item ? item.querySelector(".scan-history-body") : null;
            if (!item || !body) {
                return;
            }

            const willOpen = !item.classList.contains("is-open");
            document.querySelectorAll("#scanHistoryAccordion .scan-history-item").forEach(function (node) {
                const nodeBody = node.querySelector(".scan-history-body");
                const nodeTrigger = node.querySelector(".scan-history-trigger");
                node.classList.remove("is-open");
                if (nodeBody) {
                    nodeBody.hidden = true;
                }
                if (nodeTrigger) {
                    nodeTrigger.setAttribute("aria-expanded", "false");
                }
            });

            if (!willOpen) {
                return;
            }

            item.classList.add("is-open");
            body.hidden = false;
            trigger.setAttribute("aria-expanded", "true");
            await loadHistoryScanDetails(item);
        });
    });

    document.querySelectorAll("#scanHistoryAccordion .scan-history-item.is-open").forEach(function (item) {
        loadHistoryScanDetails(item);
    });

    if (modal) {
        modal.addEventListener("click", function (event) {
            if (event.target === modal) {
                modal.classList.remove("show");
                syncBodyOverflow();
            }
        });
    }

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
            if (modal && modal.classList.contains("show")) {
                modal.classList.remove("show");
                syncBodyOverflow();
            } else if (mobileQuery.matches && isSidebarOpen()) {
                setSidebarState(false);
            }
        }
    });

    // ── Generic independent accordion (admin page) ──────────────────────────
    document.querySelectorAll(".js-accordion-container").forEach(function (container) {
        container.addEventListener("click", function (event) {
            var trigger = event.target.closest(".js-accordion-trigger");
            if (!trigger) { return; }
            var item = trigger.closest(".js-accordion-item");
            if (!item) { return; }
            var body = item.querySelector(".js-accordion-body");
            if (!body) { return; }
            var isOpen = item.classList.contains("is-open");
            item.classList.toggle("is-open", !isOpen);
            body.hidden = isOpen;
            trigger.setAttribute("aria-expanded", String(!isOpen));
        });
    });

    // ── Machine card toggle (vulnerabilities page) ───────────────────────────
    document.querySelectorAll(".machine-card-toggle").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var card = btn.closest(".vulnerability-machine-card");
            if (!card) { return; }
            var body = card.querySelector(".machine-card-body");
            if (!body) { return; }
            var isOpen = !body.hidden;
            body.hidden = isOpen;
            btn.setAttribute("aria-expanded", String(!isOpen));
        });
    });

    // ── Machine severity filter (vulnerabilities page) ───────────────────────
    document.querySelectorAll(".machine-severity-chip").forEach(function (chip) {
        chip.addEventListener("click", function () {
            var card = chip.closest(".vulnerability-machine-card");
            if (!card) { return; }

            var body = card.querySelector(".machine-card-body");
            var toggleBtn = card.querySelector(".machine-card-toggle");
            if (body && body.hidden) {
                body.hidden = false;
                if (toggleBtn) { toggleBtn.setAttribute("aria-expanded", "true"); }
            }

            var filterValue = chip.dataset.machineFilter;
            var allChips = card.querySelectorAll(".machine-severity-chip");
            var isActive = chip.classList.contains("is-active");
            allChips.forEach(function (c) { c.classList.remove("is-active"); });
            var activeFilter = isActive ? "" : filterValue;
            if (!isActive) { chip.classList.add("is-active"); }

            var rows = card.querySelectorAll("tbody tr[data-severity]");
            rows.forEach(function (row) {
                row.hidden = activeFilter !== "" && row.dataset.severity !== activeFilter;
            });
        });
    });

    // ── Target quick-filter (targets page) ───────────────────────────────────
    document.querySelectorAll(".target-filter-chip").forEach(function (chip) {
        chip.addEventListener("click", function () {
            document.querySelectorAll(".target-filter-chip").forEach(function (c) {
                c.classList.remove("is-active");
            });
            chip.classList.add("is-active");

            var filter = chip.dataset.targetFilter;
            var rows = document.querySelectorAll("tr[data-target-risk]");
            rows.forEach(function (row) {
                if (filter === "") {
                    row.hidden = false;
                } else if (filter === "no-scan") {
                    row.hidden = row.dataset.targetHasScan === "true";
                } else {
                    row.hidden = row.dataset.targetRisk !== filter;
                }
            });
        });
    });
});
