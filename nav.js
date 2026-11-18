const menus = [...document.querySelectorAll(".nav-menu")];

for (const menu of menus) {
  menu.addEventListener("toggle", () => {
    if (!menu.open) return;
    for (const other of menus) {
      if (other !== menu) other.open = false;
    }
  });
}

document.addEventListener("click", (event) => {
  for (const menu of menus) {
    if (!menu.contains(event.target)) menu.open = false;
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  for (const menu of menus) {
    if (!menu.open) continue;
    menu.open = false;
    menu.querySelector("summary")?.focus();
  }
});
