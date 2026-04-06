document.addEventListener("DOMContentLoaded", function () {
    const body = document.body;
    const toggleBtn = document.getElementById("themeToggleBtn");
    const storageKey = "cveye_theme";

    function applyTheme(theme) {
        body.classList.remove("theme-dark", "theme-light");
        body.classList.add(theme);

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
            const newTheme = body.classList.contains("theme-dark")
                ? "theme-light"
                : "theme-dark";

            localStorage.setItem(storageKey, newTheme);
            applyTheme(newTheme);
        });
    }
});