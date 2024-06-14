/* DeliverCheck lightweight UI helpers (clipboard copy + suggestion fill). */
(function () {
  "use strict";

  async function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    document.body.removeChild(area);
  }

  document.addEventListener("htmx:beforeSwap", function (event) {
    const status = event.detail && event.detail.xhr ? event.detail.xhr.status : 0;
    if (status === 400 || status === 404 || status === 429) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });

  document.addEventListener("click", async function (event) {
    const copyBtn = event.target.closest("[data-copy-text], [data-copy-target]");
    if (copyBtn) {
      let text = copyBtn.getAttribute("data-copy-text");
      if (text === null) {
        const targetId = copyBtn.getAttribute("data-copy-target");
        const targetEl = targetId ? document.getElementById(targetId) : null;
        if (targetEl) {
          text = targetEl.value !== undefined ? targetEl.value : targetEl.textContent;
        }
      }
      if (!text) return;
      try {
        await writeClipboard(text);
        const original = copyBtn.getAttribute("data-original-label") || copyBtn.textContent.trim();
        copyBtn.setAttribute("data-original-label", original);
        copyBtn.textContent = "Copied";
        window.setTimeout(function () {
          copyBtn.textContent = original;
        }, 1600);
      } catch (_err) {
        copyBtn.textContent = "Copy failed";
      }
      return;
    }

    const fillBtn = event.target.closest("[data-fill-domain]");
    if (fillBtn) {
      const suggested = fillBtn.getAttribute("data-fill-domain");
      const input = document.getElementById("domain-input");
      if (suggested && input) {
        input.value = suggested;
        input.focus();
      }
    }
  });
})();
