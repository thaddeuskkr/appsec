(() => {
    const storageKey = "bookworms.theme";

    function readStoredTheme() {
        try {
            const theme = localStorage.getItem(storageKey);
            return theme === "light" || theme === "dark" ? theme : null;
        } catch {
            return null;
        }
    }

    function saveTheme(theme) {
        try {
            localStorage.setItem(storageKey, theme);
        } catch {
            // Ignore storage write failures (private mode, blocked storage, etc.)
        }
    }

    function preferredTheme() {
        const stored = readStoredTheme();
        if (stored) {
            return stored;
        }

        return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }

    function setTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        document.documentElement.style.colorScheme = theme;
        refreshThemeControls(theme);
    }

    function refreshThemeControls(theme) {
        document.querySelectorAll("[data-theme-toggle]").forEach((toggleButton) => {
            const icon = toggleButton.querySelector("[data-theme-icon]");
            const label = toggleButton.querySelector("[data-theme-label]");
            const isDark = theme === "dark";

            if (icon) {
                icon.classList.toggle("bi-moon-stars-fill", !isDark);
                icon.classList.toggle("bi-sun-fill", isDark);
            }

            if (label) {
                label.textContent = isDark ? "Light mode" : "Dark mode";
            }

            toggleButton.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
        });
    }

    function bindThemeToggle() {
        document.querySelectorAll("[data-theme-toggle]").forEach((toggleButton) => {
            if (toggleButton.dataset.bound === "1") {
                return;
            }

            toggleButton.dataset.bound = "1";
            toggleButton.addEventListener("click", () => {
                const current = document.documentElement.getAttribute("data-theme") || preferredTheme();
                const next = current === "dark" ? "light" : "dark";
                setTheme(next);
                saveTheme(next);
            });
        });
    }

    document.addEventListener("DOMContentLoaded", () => {
        setTheme(document.documentElement.getAttribute("data-theme") || preferredTheme());
        bindThemeToggle();

        const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
        const applySystemTheme = (event) => {
            if (!readStoredTheme()) {
                setTheme(event.matches ? "dark" : "light");
            }
        };

        if (typeof mediaQuery.addEventListener === "function") {
            mediaQuery.addEventListener("change", applySystemTheme);
        } else if (typeof mediaQuery.addListener === "function") {
            mediaQuery.addListener(applySystemTheme);
        }
    });
})();
