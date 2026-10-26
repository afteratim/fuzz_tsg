document.addEventListener("DOMContentLoaded", function () {
  const picker = document.getElementById("documents");
  const display = document.getElementById("selected-files");
  if (!picker || !display) return;
  picker.addEventListener("change", function () {
    const files = Array.from(picker.files || []);
    if (!files.length) {
      display.textContent = "No files selected";
      return;
    }
    display.textContent = files.map(f => `${f.name} — ${(f.size / (1024 * 1024)).toFixed(2)} MB`).join(" · ");
    if (files.length !== 2) display.textContent += " · Select exactly two files.";
    if (files.some(f => f.size > 25 * 1024 * 1024)) display.textContent += " · One or more files exceed 25 MB.";
  });
});
