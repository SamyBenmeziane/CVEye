document.addEventListener("DOMContentLoaded", function () {
    const modal = document.getElementById("scanDetailsModal");
    const openBtn = document.getElementById("openDetailsBtn");
    const closeBtn = document.getElementById("closeDetailsBtn");

    const appLayout = document.getElementById("appLayout");
    const sidebarToggle = document.getElementById("sidebarToggle");

    if (sidebarToggle && appLayout) {
        sidebarToggle.addEventListener("click", function () {
            if (appLayout.classList.contains("sidebar-open")) {
                appLayout.classList.remove("sidebar-open");
                appLayout.classList.add("sidebar-closed");
            } else {
                appLayout.classList.remove("sidebar-closed");
                appLayout.classList.add("sidebar-open");
            }
        });
    }

    if (openBtn && modal) {
        openBtn.addEventListener("click", function () {
            modal.classList.add("show");
            document.body.style.overflow = "hidden";
        });
    }

    if (closeBtn && modal) {
        closeBtn.addEventListener("click", function () {
            modal.classList.remove("show");
            document.body.style.overflow = "";
        });
    }

    if (modal) {
        modal.addEventListener("click", function (event) {
            if (event.target === modal) {
                modal.classList.remove("show");
                document.body.style.overflow = "";
            }
        });
    }

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && modal) {
            modal.classList.remove("show");
            document.body.style.overflow = "";
        }
    });
});
