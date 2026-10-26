document.addEventListener("DOMContentLoaded", function () {
  const category = document.getElementById("gst-category-filter");
  const priority = document.getElementById("gst-priority-filter");
  const search = document.getElementById("gst-search");
  const table = document.getElementById("gst-results-table");
  const count = document.getElementById("gst-visible-count");
  if (!category || !priority || !search || !table || !count) return;

  let sortColumn = -1;
  let sortDirection = "ascending";

  function applyFilters() {
    const cat = category.value;
    const pri = priority.value;
    const query = search.value.trim().toLowerCase();
    let visible = 0;
    const rows = table.querySelectorAll("tbody tr");
    rows.forEach(function (row) {
      const rowCat = row.dataset.category || "";
      const rowPri = row.dataset.priority || "";
      const textMatch = !query || row.textContent.toLowerCase().includes(query);
      const catMatch = cat === "all" ||
        (cat === "__all_discrepancies__" && rowCat !== "Matched") || rowCat === cat;
      const priorityMatch = pri === "all" ||
        (pri === "high" && rowPri === "high") ||
        (pri === "review" && rowPri === "review") ||
        (pri === "other" && rowPri === "other");
      const show = textMatch && catMatch && priorityMatch;
      row.hidden = !show;
      if (show) visible++;
    });
    count.textContent = "Showing " + visible + " of " + rows.length + " records";
  }

  function cellSortValue(row, index) {
    const cell = row.cells[index];
    if (!cell) return "";
    const raw = cell.textContent.trim();
    if ([6, 7, 8, 9, 10].includes(index)) {
      const numeric = Number(raw.replace(/[^0-9.-]/g, ""));
      return Number.isFinite(numeric) ? numeric : Number.NEGATIVE_INFINITY;
    }
    return raw.toLocaleLowerCase();
  }

  table.querySelectorAll(".sort-button").forEach(function (button) {
    button.setAttribute("aria-sort", "none");
    button.addEventListener("click", function () {
      const index = Number(button.dataset.sort);
      if (sortColumn === index) {
        sortDirection = sortDirection === "ascending" ? "descending" : "ascending";
      } else {
        sortColumn = index;
        sortDirection = "ascending";
      }
      table.querySelectorAll(".sort-button").forEach(function (other) {
        other.setAttribute("aria-sort", "none");
        const icon = other.querySelector("span");
        if (icon) icon.textContent = "↕";
      });
      button.setAttribute("aria-sort", sortDirection);
      const icon = button.querySelector("span");
      if (icon) icon.textContent = sortDirection === "ascending" ? "↑" : "↓";
      const tbody = table.querySelector("tbody");
      const rows = Array.from(tbody.rows);
      rows.sort(function (a, b) {
        const av = cellSortValue(a, index);
        const bv = cellSortValue(b, index);
        let cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv), undefined, {numeric: true, sensitivity: "base"});
        return sortDirection === "ascending" ? cmp : -cmp;
      });
      rows.forEach(function (row) { tbody.appendChild(row); });
      applyFilters();
    });
  });

  category.addEventListener("change", applyFilters);
  priority.addEventListener("change", applyFilters);
  search.addEventListener("input", applyFilters);
  document.querySelectorAll("[data-filter-category]").forEach(function (button) {
    button.addEventListener("click", function () {
      category.value = button.dataset.filterCategory;
      document.querySelectorAll("[data-filter-category]").forEach(function (b) { b.classList.remove("active"); });
      button.classList.add("active");
      applyFilters();
      table.scrollIntoView({behavior: "smooth", block: "start"});
    });
  });
  applyFilters();
});
