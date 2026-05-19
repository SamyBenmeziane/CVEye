// Application immediate du theme sur <html> pour eviter le flash au chargement
(function () {
    try {
        var saved = localStorage.getItem("cveye_theme") || "theme-dark";
        document.documentElement.classList.add(saved);
    } catch (e) {}
})();

document.addEventListener("DOMContentLoaded", function () {
    const html = document.documentElement;
    const toggleBtn = document.getElementById("themeToggleBtn");
    const storageKey = "cveye_theme";

    function applyTheme(theme) {
        html.classList.remove("theme-dark", "theme-light");
        html.classList.add(theme);

        if (toggleBtn) {
            toggleBtn.textContent =
                theme === "theme-dark"
                    ? "Basculer en mode clair"
                    : "Basculer en mode sombre";
        }
    }

    const savedTheme = localStorage.getItem(storageKey) || "theme-dark";
    applyTheme(savedTheme);

    if (toggleBtn) {
        toggleBtn.addEventListener("click", function () {
            const newTheme = html.classList.contains("theme-dark")
                ? "theme-light"
                : "theme-dark";

            localStorage.setItem(storageKey, newTheme);
            applyTheme(newTheme);
        });
    }
});
