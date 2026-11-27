"use strict";

document.addEventListener("click", (event) => {
  for (const menu of document.querySelectorAll(".account-menu[open]")) {
    if (!menu.contains(event.target)) menu.open = false;
  }
});
