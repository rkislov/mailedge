(() => {
  const root = document.documentElement;
  const storageKey = "mailedge-theme";

  function storedTheme() {
    try {
      return localStorage.getItem(storageKey);
    } catch {
      return null;
    }
  }

  function setTheme(theme) {
    root.dataset.theme = theme === "light" ? "light" : "dark";
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.textContent = root.dataset.theme === "light" ? button.dataset.darkLabel : button.dataset.lightLabel;
    });
    document.dispatchEvent(new Event("mailedge:themechange"));
  }

  setTheme(storedTheme());
  document.addEventListener("DOMContentLoaded", () => {
    setTheme(storedTheme());
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.hidden = false;
      button.addEventListener("click", () => {
        const theme = root.dataset.theme === "light" ? "dark" : "light";
        try {
          localStorage.setItem(storageKey, theme);
        } catch {
          // The current page can still switch when storage is unavailable.
        }
        setTheme(theme);
      });
    });
  });
  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) setTheme(storedTheme());
  });
})();
