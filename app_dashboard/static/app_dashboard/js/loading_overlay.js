document.addEventListener("DOMContentLoaded", function () {
    function shouldShowGlobalLoadingForForm(form) {
        if (!form) {
            return false;
        }

        const method = (form.getAttribute("method") || "get").toLowerCase();
        const action = form.getAttribute("action") || "";

        if (method !== "post") {
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

    const forms = document.querySelectorAll("form");
    forms.forEach(function (form) {
        form.addEventListener("submit", function () {
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
});
