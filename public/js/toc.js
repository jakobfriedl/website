(() => {
  // <stdin>
  (function() {
    "use strict";
    function initToc() {
      const sidebarLinks = document.querySelectorAll(".toc-sidebar a");
      const mobileLinks = document.querySelectorAll(".toc-mobile a");
      const allLinks = [...sidebarLinks, ...mobileLinks];
      if (allLinks.length === 0) return;
      const tocIds = /* @__PURE__ */ new Set();
      allLinks.forEach(function(link) {
        var href = link.getAttribute("href");
        if (href && href.startsWith("#")) tocIds.add(href.slice(1));
      });
      const headings = Array.from(
        document.querySelectorAll("h1[id], h2[id], h3[id], h4[id], h5[id], h6[id]")
      );
      if (headings.length === 0) return;
      function resolveId(idx) {
        if (tocIds.has(headings[idx].id)) return headings[idx].id;
        for (var i = idx - 1; i >= 0; i--) {
          if (tocIds.has(headings[i].id)) return headings[i].id;
        }
        return null;
      }
      var activeId = null;
      function setActive(id) {
        if (!id || activeId === id) return;
        activeId = id;
        allLinks.forEach(function(link) {
          link.classList.remove("toc-active");
          if (link.getAttribute("href") === "#" + id) {
            link.classList.add("toc-active");
          }
        });
      }
      function onScroll() {
        var atBottom = window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 8;
        if (atBottom) {
          for (var j = headings.length - 1; j >= 0; j--) {
            var lastId = resolveId(j);
            if (lastId) {
              setActive(lastId);
              return;
            }
          }
          return;
        }
        var current = null;
        var currentIdx = -1;
        for (var i = 0; i < headings.length; i++) {
          if (headings[i].getBoundingClientRect().top - 120 <= 0) {
            current = headings[i];
            currentIdx = i;
          } else {
            break;
          }
        }
        if (current) {
          var id = resolveId(currentIdx);
          if (id) setActive(id);
        }
      }
      window.addEventListener("scroll", onScroll, { passive: true });
      onScroll();
    }
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initToc);
    } else {
      initToc();
    }
  })();
})();
