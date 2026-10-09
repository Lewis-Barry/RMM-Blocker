const toggle = document.getElementById("theme-toggle");

toggle.addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme !== "light";
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  toggle.textContent = dark ? "Dark theme" : "Light theme";
  toggle.setAttribute("aria-label", `Switch to ${dark ? "dark" : "light"} theme`);
});
