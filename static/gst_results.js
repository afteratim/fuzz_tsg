document.addEventListener("DOMContentLoaded", function () {
  const category = document.getElementById("gst-category-filter");
  const priority = document.getElementById("gst-priority-filter");
  const search = document.getElementById("gst-search");
  const table = document.getElementById("gst-results-table");
  const count = document.getElementById("gst-visible-count");
  if (!category || !priority || !search || !table || !count) return;

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
        (cat === "__all_discrepancies__" && rowCat !== "Matched") ||
        rowCat === cat;
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
  category.addEventListener("change", applyFilters);
  priority.addEventListener("change", applyFilters);
  search.addEventListener("input", applyFilters);
  document.querySelectorAll("[data-filter-category]").forEach(function (button) {
    button.addEventListener("click", function () {
      category.value = button.dataset.filterCategory;
      applyFilters();
      document.getElementById("gst-results-table").scrollIntoView({behavior: "smooth", block: "start"});
    });
  });
  applyFilters();
});
