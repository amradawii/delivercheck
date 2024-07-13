/* DeliverCheck lightweight UI helpers (clipboard copy, suggestion fill, accessibility). */
(function () {
  "use strict";

  function announce(message) {
    const region = document.getElementById("sr-announcer");
    if (!region) return;
    region.textContent = "";
    window.setTimeout(function () {
      region.textContent = message;
    }, 20);
  }

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
    if (status === 400 || status === 404 || status === 429 || status === 504) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });

  function showNetworkFallback(event) {
    const target = event.detail && event.detail.target;
    if (!target) return;
    target.innerHTML =
      '<div class="rounded-lg border border-zinc-200 p-5" role="alert">' +
      '<p class="text-sm font-semibold text-zinc-950">This check could not finish</p>' +
      '<p class="mt-1 text-sm text-zinc-700">The request timed out or lost connection. Run the check again in a moment.</p>' +
      "</div>";
    announce("This check could not finish. Please try again.");
  }

  document.addEventListener("htmx:sendError", showNetworkFallback);
  document.addEventListener("htmx:responseError", function (event) {
    const status = event.detail && event.detail.xhr ? event.detail.xhr.status : 0;
    if (status >= 500 && status !== 504) {
      showNetworkFallback(event);
    }
  });

  document.addEventListener("change", function (event) {
    const portSelect = event.target.closest("#send-port-mode");
    if (!portSelect) return;
    const modeSelect = document.getElementById("send-security-mode");
    if (!modeSelect) return;
    if (portSelect.value === "465") {
      modeSelect.value = "implicit_tls";
    } else if (portSelect.value === "587") {
      modeSelect.value = "starttls";
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
        announce("Copied to clipboard.");
        window.setTimeout(function () {
          copyBtn.textContent = original;
        }, 1600);
      } catch (_err) {
        copyBtn.textContent = "Copy failed";
        announce("Could not copy to clipboard.");
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
