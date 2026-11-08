/* Encrypted-vault client for the public gamebook pages.
 *
 * Contract (plan section 12.5):
 *   file  : 40-byte big-endian header, then AES-256-GCM ciphertext || tag
 *   header: 0..3 "AGB1", 4 version=1, 5 kdf_id=1 (PBKDF2-SHA256),
 *           6..9 iterations, 10 salt_len=16, 11..26 salt,
 *           27 iv_len=12, 28..39 iv, AAD = header[0..40]
 *
 * Unlocking reports four stages: download, key derivation, decryption and
 * rendering. PBKDF2 runs in vault-worker.js so the page stays responsive.
 * The passphrase never leaves memory here and no plaintext is written to
 * localStorage, IndexedDB, the URL or the console. The decrypted pack is
 * handed to window.AGBReader.applyPack for the lifetime of the page only.
 */
(function () {
  "use strict";

  var MAGIC = "AGB1";
  var HEADER_BYTES = 40;
  var TAG_BYTES = 16;
  var VERSION = 1;
  var KDF_PBKDF2_SHA256 = 1;
  var SALT_LEN = 16;
  var IV_LEN = 12;
  var MIN_ITERATIONS = 310000;
  var MAX_ITERATIONS = 10000000;

  var STAGES = ["download", "derive", "decrypt", "render"];
  var STAGE_LABEL = {
    download: "Downloading encrypted text (1/4)",
    derive: "Deriving key (2/4)",
    decrypt: "Decrypting (3/4)",
    render: "Applying the Chinese edition (4/4)"
  };

  var WORKER_URL = null;
  if (typeof document !== "undefined" && document.currentScript) {
    var script = document.currentScript;
    var workerName =
      script.getAttribute("data-agb-worker") || "vault-worker.js";
    if (script.src) {
      try {
        WORKER_URL = new URL(workerName, script.src).href;
      } catch (err) {
        WORKER_URL = null;
      }
    }
  }

  function vaultError(code, message) {
    var err = new Error(message || code);
    err.code = code;
    return err;
  }

  function now() {
    if (typeof performance !== "undefined" && performance.now) {
      return performance.now();
    }
    return Date.now();
  }

  function formatBytes(value) {
    var n = Number(value) || 0;
    if (n < 1024) return n + " B";
    if (n < 1048576) return Math.round(n / 1024) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  }

  function wipe(buffer) {
    if (!buffer) return;
    try {
      var view =
        buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
      if (view && typeof view.fill === "function") view.fill(0);
    } catch (err) {
      /* best effort */
    }
  }

  function isAbort(err, signal) {
    return (
      (signal && signal.aborted) ||
      (err && (err.name === "AbortError" || err.code === "E_CANCELLED"))
    );
  }

  function throwIfAborted(signal) {
    if (signal && signal.aborted) {
      throw vaultError("E_CANCELLED", "Unlock canceled.");
    }
  }

  function checkCrypto() {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      throw vaultError(
        "E_UNSUPPORTED",
        "Decryption needs a secure page (https or localhost)."
      );
    }
  }

  function checkPassphrase(passphrase) {
    if (typeof passphrase !== "string" || !passphrase) {
      throw vaultError("E_BAD_PASSPHRASE", "A passphrase is required.");
    }
  }

  async function toBytes(input) {
    if (input instanceof Uint8Array) return input;
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    if (ArrayBuffer.isView(input)) {
      return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }
    if (input && typeof input.arrayBuffer === "function") {
      return new Uint8Array(await input.arrayBuffer());
    }
    throw vaultError("E_BAD_HEADER", "No ciphertext buffer was provided.");
  }

  function parseHeader(bytes) {
    if (bytes.length < HEADER_BYTES + TAG_BYTES) {
      throw vaultError("E_BAD_HEADER", "The encrypted file is too short.");
    }
    if (String.fromCharCode.apply(null, bytes.subarray(0, 4)) !== MAGIC) {
      throw vaultError("E_BAD_HEADER", "Unknown encrypted-file magic.");
    }
    if (bytes[4] !== VERSION) {
      throw vaultError("E_UNSUPPORTED_VERSION", "Unsupported vault version.");
    }
    if (bytes[5] !== KDF_PBKDF2_SHA256) {
      throw vaultError("E_UNSUPPORTED_VERSION", "Unsupported key derivation.");
    }
    var iterations =
      ((bytes[6] << 24) | (bytes[7] << 16) | (bytes[8] << 8) | bytes[9]) >>> 0;
    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
      throw vaultError("E_BAD_HEADER", "Invalid key-derivation cost.");
    }
    if (bytes[10] !== SALT_LEN) {
      throw vaultError("E_BAD_HEADER", "Invalid salt length.");
    }
    if (bytes[27] !== IV_LEN) {
      throw vaultError("E_BAD_HEADER", "Invalid IV length.");
    }
    return {
      version: bytes[4],
      iterations: iterations,
      salt: bytes.subarray(11, 27),
      iv: bytes.subarray(28, 40),
      aad: bytes.subarray(0, HEADER_BYTES),
      ciphertext: bytes.subarray(HEADER_BYTES)
    };
  }

  /* ---------------- progress reporting ---------------- */

  function emitProgress(options, stage, fraction, detail, pctText) {
    if (!options || typeof options.onProgress !== "function") return;
    try {
      options.onProgress({
        stage: stage,
        fraction: fraction,
        detail: detail || "",
        pctText: pctText
      });
    } catch (err) {
      /* the host UI must never break decryption */
    }
  }

  /* The derivation phase gets an elapsed-time creep capped below 100%.
     Completion is only reported after WebCrypto actually resolves. */
  function startElapsedCreep(onTick) {
    var started = now();
    var timer = setInterval(function () {
      var elapsed = (now() - started) / 1000;
      var fraction = 0.9 * (1 - Math.exp(-elapsed / 0.9));
      onTick(fraction, elapsed);
    }, 120);
    return function stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    };
  }

  /* ---------------- download with content-length progress ------------ */

  async function downloadBytes(url, signal, options) {
    throwIfAborted(signal);
    emitProgress(options, "download", 0, "Starting download", "0%");

    var response;
    try {
      response = await fetch(url, {
        cache: "no-store",
        credentials: "same-origin",
        signal: signal
      });
    } catch (err) {
      if (isAbort(err, signal)) throw vaultError("E_CANCELLED", "Unlock canceled.");
      throw vaultError("E_FETCH", "Could not download the encrypted edition.");
    }
    if (!response.ok) {
      throw vaultError("E_FETCH", "Could not download the encrypted edition.");
    }

    var total = 0;
    var rawLength = response.headers.get("content-length");
    if (rawLength) {
      total = Number.parseInt(rawLength, 10);
      if (!(total > 0)) total = 0;
    }

    if (!response.body || typeof response.body.getReader !== "function") {
      var whole = await response.arrayBuffer();
      throwIfAborted(signal);
      emitProgress(
        options, "download", 1,
        total
          ? formatBytes(whole.byteLength) + " of " + formatBytes(total)
          : formatBytes(whole.byteLength),
        "100%"
      );
      return new Uint8Array(whole);
    }

    var reader = response.body.getReader();
    var chunks = [];
    var received = 0;
    try {
      while (true) {
        var step = await reader.read();
        if (step.done) break;
        throwIfAborted(signal);
        if (step.value && step.value.length) {
          chunks.push(step.value);
          received += step.value.length;
        }
        if (total) {
          emitProgress(
            options, "download",
            Math.min(0.999, received / total),
            formatBytes(received) + " of " + formatBytes(total),
            Math.min(99, Math.round((received / total) * 100)) + "%"
          );
        } else {
          emitProgress(
            options, "download", null,
            formatBytes(received) + " downloaded",
            "\u2026"
          );
        }
      }
    } catch (err) {
      if (isAbort(err, signal)) throw vaultError("E_CANCELLED", "Unlock canceled.");
      throw vaultError("E_FETCH", "Could not download the encrypted edition.");
    }

    var bytes = new Uint8Array(received);
    var offset = 0;
    for (var i = 0; i < chunks.length; i++) {
      bytes.set(chunks[i], offset);
      offset += chunks[i].length;
    }
    emitProgress(
      options, "download", 1,
      total
        ? formatBytes(received) + " of " + formatBytes(total)
        : formatBytes(received),
      "100%"
    );
    return bytes;
  }

  /* ---------------- PBKDF2 in a worker -------------------------------- */

  var workerId = 0;

  function canUseWorker() {
    return !!(WORKER_URL && typeof Worker === "function");
  }

  function runWorker(header, ciphertext, passphrase, onStage, signal) {
    return new Promise(function (resolve, reject) {
      throwIfAborted(signal);
      var worker;
      try {
        worker = new Worker(WORKER_URL);
      } catch (err) {
        reject(vaultError("E_WORKER", "The decryption worker could not start."));
        return;
      }

      var id = ++workerId;
      var settled = false;

      function finish(fn, value) {
        if (settled) return;
        settled = true;
        if (signal) signal.removeEventListener("abort", onAbort);
        if (worker) {
          worker.terminate();
          worker = null;
        }
        fn(value);
      }

      function onAbort() {
        finish(reject, vaultError("E_CANCELLED", "Unlock canceled."));
      }

      if (signal) signal.addEventListener("abort", onAbort);

      worker.onmessage = function (event) {
        var message = event.data || {};
        if (message.id !== id) return;
        if (message.type === "stage") {
          if (typeof onStage === "function") onStage(message.stage);
          return;
        }
        if (message.type === "done") {
          finish(resolve, message.plain);
          return;
        }
        if (message.type === "error") {
          finish(
            reject,
            vaultError(
              message.code || "E_UNSUPPORTED",
              "The decryption worker could not finish."
            )
          );
        }
      };
      worker.onerror = function () {
        finish(reject, vaultError("E_WORKER", "The decryption worker could not start."));
      };

      try {
        worker.postMessage(
          {
            type: "decrypt",
            id: id,
            passphrase: passphrase,
            iterations: header.iterations,
            salt: header.salt,
            iv: header.iv,
            aad: header.aad,
            ciphertext: ciphertext.buffer
          },
          [ciphertext.buffer]
        );
      } catch (err) {
        finish(reject, vaultError("E_WORKER", "The decryption worker could not start."));
      }
    });
  }

  async function decryptOnMainThread(header, passphrase, onStage, signal) {
    var subtle = globalThis.crypto.subtle;
    throwIfAborted(signal);
    var material = await subtle.importKey(
      "raw",
      new TextEncoder().encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    throwIfAborted(signal);
    var key = await subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: header.salt,
        iterations: header.iterations
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    if (typeof onStage === "function") onStage("decrypt");
    throwIfAborted(signal);
    try {
      return await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: header.iv,
          additionalData: header.aad,
          tagLength: 128
        },
        key,
        header.ciphertext
      );
    } catch (err) {
      throw vaultError("E_BAD_PASSPHRASE", "The passphrase did not unlock this file.");
    }
  }

  async function decryptBytes(bytes, header, passphrase, options) {
    var signal = options && options.signal;
    throwIfAborted(signal);

    emitProgress(options, "derive", 0, "Deriving the key", "\u2026");
    var stopCreep = startElapsedCreep(function (fraction, elapsed) {
      emitProgress(
        options, "derive", fraction,
        "Elapsed " + elapsed.toFixed(1) + "s",
        elapsed.toFixed(1) + "s"
      );
    });

    var onStage = function (stage) {
      if (stage !== "decrypt") return;
      stopCreep();
      emitProgress(options, "derive", 1, "Key derived", "100%");
      emitProgress(options, "decrypt", 0, "Verifying the passphrase", "\u2026");
    };

    var plain;
    try {
      if (canUseWorker()) {
        var ciphertext = new Uint8Array(header.ciphertext.length);
        ciphertext.set(header.ciphertext);
        try {
          plain = await runWorker(header, ciphertext, passphrase, onStage, signal);
        } catch (err) {
          if (!err || err.code !== "E_WORKER" || (signal && signal.aborted)) {
            throw err;
          }
          // Worker failed to load; keep the page usable with the same KDF.
          emitProgress(options, "derive", 0, "Deriving the key on the page", "\u2026");
          plain = await decryptOnMainThread(header, passphrase, onStage, signal);
        }
      } else {
        plain = await decryptOnMainThread(header, passphrase, onStage, signal);
      }
    } finally {
      stopCreep();
    }

    if (signal && signal.aborted) {
      wipe(plain);
      throw vaultError("E_CANCELLED", "Unlock canceled.");
    }

    emitProgress(options, "derive", 1, "Key derived", "100%");
    emitProgress(options, "decrypt", 1, "Passphrase verified", "100%");
    emitProgress(options, "render", 0.1, "Preparing the Chinese edition", "\u2026");

    var text;
    try {
      text = new TextDecoder("utf-8").decode(plain);
    } catch (err) {
      wipe(plain);
      throw vaultError("E_BAD_PACK", "The decrypted payload is not valid text.");
    }
    wipe(plain);

    var pack;
    try {
      pack = JSON.parse(text);
    } catch (err) {
      throw vaultError("E_BAD_PACK", "The decrypted payload is not valid JSON.");
    }
    if (!pack || typeof pack !== "object" ||
        !pack.sections || typeof pack.sections !== "object") {
      throw vaultError("E_BAD_PACK", "The file is not a readable book pack.");
    }
    throwIfAborted(signal);
    emitProgress(options, "render", 0.6, "Applying the Chinese edition", "\u2026");
    return { version: header.version, pack: pack };
  }

  async function decryptVault(buffer, passphrase, options) {
    checkCrypto();
    checkPassphrase(passphrase);
    var bytes = await toBytes(buffer);
    var header = parseHeader(bytes);
    return decryptBytes(bytes, header, passphrase, options || {});
  }

  async function unlockFromUrl(url, passphrase, options) {
    var opts = options || {};
    checkCrypto();
    checkPassphrase(passphrase);
    var bytes = await downloadBytes(url, opts.signal, opts);
    var header = parseHeader(bytes);
    return decryptBytes(bytes, header, passphrase, opts);
  }

  var ERROR_TEXT = {
    E_BAD_PASSPHRASE: "Incorrect passphrase",
    E_FETCH: "Could not download the encrypted edition.",
    E_BAD_PACK: "That file is not a readable book pack.",
    E_BAD_HEADER: "The encrypted edition is not readable.",
    E_UNSUPPORTED_VERSION: "The encrypted edition is not readable.",
    E_UNSUPPORTED: "Unlocking needs a secure page (https or localhost).",
    E_UI: "The Chinese interface could not be loaded. Check your connection and try again.",
    E_CANCELLED: "Unlock canceled."
  };

  function messageFor(err) {
    return ERROR_TEXT[(err && err.code) || ""] ||
      "Could not unlock the full text.";
  }

  /* ---------------- shared progress component ------------------------- */

  function createProgress(root) {
    if (!root) return null;

    var bar = root.querySelector(".agb-progress-bar");
    var labelEl = root.querySelector(".agb-progress-label");
    var pctEl = root.querySelector(".agb-progress-pct");
    var detailEl = root.querySelector(".agb-progress-detail");
    var segments = {};
    STAGES.forEach(function (stage) {
      var wrap = root.querySelector('[data-agb-stage="' + stage + '"]');
      if (wrap) {
        segments[stage] = { wrap: wrap, fill: wrap.querySelector("i") };
      }
    });

    var current = -1;

    function reset() {
      root.hidden = true;
      current = -1;
      STAGES.forEach(function (stage) {
        var seg = segments[stage];
        if (!seg) return;
        seg.wrap.classList.remove("is-active", "is-done", "is-indeterminate");
        if (seg.fill) seg.fill.style.width = "0%";
      });
      if (labelEl) labelEl.textContent = "";
      if (pctEl) pctEl.textContent = "";
      if (detailEl) detailEl.textContent = "";
      if (bar) {
        bar.setAttribute("aria-valuenow", "0");
        bar.setAttribute("aria-valuetext", "");
      }
    }

    function show() {
      root.hidden = false;
    }

    function update(event) {
      if (!event) return;
      var stage = event.stage;
      var index = STAGES.indexOf(stage);
      if (index < 0) return;

      root.hidden = false;
      if (index !== current) {
        STAGES.forEach(function (name, i) {
          var seg = segments[name];
          if (!seg) return;
          seg.wrap.classList.remove("is-active", "is-done", "is-indeterminate");
          if (seg.fill) seg.fill.style.width = "0%";
          if (i < index) {
            seg.wrap.classList.add("is-done");
            if (seg.fill) seg.fill.style.width = "100%";
          } else if (i === index) {
            seg.wrap.classList.add("is-active");
          }
        });
        current = index;
        if (labelEl) labelEl.textContent = STAGE_LABEL[stage];
      }

      var seg = segments[stage];
      if (seg) {
        var fraction = event.fraction;
        if (fraction === null || fraction === undefined) {
          seg.wrap.classList.add("is-indeterminate");
          if (seg.fill) seg.fill.style.width = "45%";
        } else {
          seg.wrap.classList.remove("is-indeterminate");
          var clamped = Math.max(0, Math.min(1, fraction));
          if (seg.fill) seg.fill.style.width = (clamped * 100) + "%";
          if (clamped >= 1) seg.wrap.classList.add("is-done");
        }
      }

      if (pctEl) {
        if (typeof event.pctText === "string") {
          pctEl.textContent = event.pctText;
        } else if (typeof event.fraction === "number") {
          pctEl.textContent = Math.round(event.fraction * 100) + "%";
        } else {
          pctEl.textContent = "\u2026";
        }
      }
      if (detailEl && event.detail) detailEl.textContent = event.detail;

      if (bar) {
        var fractionForBar =
          typeof event.fraction === "number"
            ? Math.max(0, Math.min(1, event.fraction))
            : 0.35;
        var overall = Math.round(((index + fractionForBar) / STAGES.length) * 100);
        bar.setAttribute("aria-valuenow", String(overall));
        bar.setAttribute(
          "aria-valuetext",
          (labelEl ? labelEl.textContent : "") + " " +
            (pctEl ? pctEl.textContent : "")
        );
      }
    }

    reset();
    return { reset: reset, show: show, update: update };
  }

  /* ---------------- reader page: unlock entry + language switch -------- */

  function bootReaderUi() {
    var root = document.getElementById("agb-unlock-root");
    if (!root) return;

    var url = (root.getAttribute("data-vault-url") || "").trim();
    var book = (root.getAttribute("data-vault-book") || "").trim();
    var backdrop = document.getElementById("agb-unlock-backdrop");
    var form = document.getElementById("agb-unlock-form");
    var input = document.getElementById("agb-passphrase");
    var message = document.getElementById("agb-unlock-message");
    var submit = document.getElementById("agb-unlock-submit");
    var cancel = document.getElementById("agb-unlock-cancel");
    var unlockBtn = document.getElementById("agb-unlock-btn");
    var progress = createProgress(document.getElementById("agb-unlock-progress"));
    if (!backdrop || !form || !input || !message || !submit) return;

    var unlocked = false;
    var busy = false;
    var activeRun = 0;
    var controller = null;

    function setMessage(text, isError) {
      message.textContent = text || "";
      message.classList.toggle("is-error", !!isError);
    }

    function setBusy(on) {
      input.disabled = on;
      submit.hidden = on;
      submit.disabled = on || !url;
      submit.textContent = "Unlock";
      if (cancel) cancel.hidden = false;
    }

    // UI labels for the language switch. Chinese spellings are written as
    // escapes so the shipped script stays ASCII; they are only applied when
    // the reader is actually in Chinese mode.
    var LANG_UI = {
      en: {
        langGroup: "Language",
        unlockBtn: "Unlock full text",
        langEn: "English",
        langZh: "Chinese full text"
      },
      zh: {
        langGroup: "\u8bed\u8a00",
        unlockBtn: "\u89e3\u9501\u5168\u6587",
        langEn: "\u82f1\u6587",
        langZh: "\u4e2d\u6587\u5168\u6587"
      }
    };

    function setLang(lang) {
      Array.prototype.forEach.call(
        root.querySelectorAll("[data-agb-lang]"),
        function (btn) {
          btn.setAttribute(
            "aria-pressed",
            btn.getAttribute("data-agb-lang") === lang ? "true" : "false"
          );
        }
      );
      var copy = LANG_UI[lang] || LANG_UI.en;
      Array.prototype.forEach.call(
        root.querySelectorAll("[data-agb-ui]"),
        function (el) {
          var key = el.getAttribute("data-agb-ui");
          if (key === "langGroup") el.setAttribute("aria-label", copy.langGroup);
          else if (copy[key] != null) el.textContent = copy[key];
        }
      );
      if (unlockBtn) unlockBtn.hidden = lang === "zh";
    }

    function abandonRun() {
      if (!busy) return;
      activeRun++;
      busy = false;
      if (controller) {
        controller.abort();
        controller = null;
      }
      if (progress) progress.reset();
      setMessage("", false);
      input.value = "";
      setBusy(false);
    }

    function openDialog() {
      if (busy || unlocked) return;
      setMessage("", false);
      input.value = "";
      if (progress) progress.reset();
      backdrop.hidden = false;
      setBusy(false);
      if (!url) {
        setMessage("The encrypted full text is not published yet.", true);
      }
      window.setTimeout(function () {
        if (url) input.focus();
      }, 30);
    }

    function closeDialog() {
      abandonRun();
      backdrop.hidden = true;
      input.value = "";
      setMessage("", false);
      if (progress) progress.reset();
      setBusy(false);
    }

    async function beginUnlock(passphrase) {
      busy = true;
      var run = ++activeRun;
      controller = new AbortController();
      setMessage("", false);
      setBusy(true);
      if (progress) {
        progress.reset();
        progress.show();
      }

      var options = {
        signal: controller.signal,
        onProgress: function (event) {
          if (run === activeRun && progress) progress.update(event);
        }
      };

      try {
        var result = await unlockFromUrl(url, passphrase, options);
        if (run !== activeRun) return;

        var pack = result.pack;
        if (book && pack.slug && pack.slug !== book) {
          throw vaultError("E_BAD_PACK", "This pack belongs to another book.");
        }
        if (!window.AGBReader || typeof window.AGBReader.applyPack !== "function") {
          throw vaultError("E_UNSUPPORTED", "This page cannot load the unlocked pack.");
        }

        var applied = await window.AGBReader.applyPack(pack);
        if (applied === false) {
          throw vaultError(
            "E_UI",
            "The Chinese interface could not be loaded."
          );
        }
        if (progress) {
          progress.update({
            stage: "render",
            fraction: 1,
            detail: "Chinese edition ready",
            pctText: "100%"
          });
        }
        unlocked = true;
        busy = false;
        controller = null;
        closeDialog();
        setLang("zh");
      } catch (err) {
        if (run !== activeRun || (err && err.code === "E_CANCELLED")) return;
        if (progress) progress.reset();
        setMessage(messageFor(err), true);
        input.value = "";
        input.focus();
      } finally {
        if (run === activeRun) {
          busy = false;
          controller = null;
          setBusy(false);
        }
      }
    }

    if (unlockBtn) unlockBtn.addEventListener("click", openDialog);
    if (cancel) cancel.addEventListener("click", closeDialog);
    backdrop.addEventListener("click", function (ev) {
      if (ev.target === backdrop) closeDialog();
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !backdrop.hidden) closeDialog();
    });

    Array.prototype.forEach.call(
      root.querySelectorAll("[data-agb-lang]"),
      function (btn) {
        btn.addEventListener("click", function () {
          var lang = btn.getAttribute("data-agb-lang");
          if (lang === "zh") {
            if (!unlocked) openDialog();
          } else if (unlocked) {
            // Reloading is the contract: the decrypted pack is never kept.
            window.location.reload();
          }
        });
      }
    );

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (busy || unlocked) return;
      if (!url) {
        openDialog();
        return;
      }
      var passphrase = input.value;
      if (!passphrase) {
        setMessage("Enter the passphrase.", true);
        input.focus();
        return;
      }
      beginUnlock(passphrase);
    });

    // A previously imported local pack may already have switched the reader
    // to Chinese before this module ran; reflect that in the switch and in
    // any later locale change (the Chinese UI asset loads asynchronously).
    if (document.documentElement.lang.toLowerCase().startsWith("zh")) {
      unlocked = true;
      setLang("zh");
    }
    document.addEventListener("agb-localechange", function (event) {
      var locale = event && event.detail && event.detail.locale;
      if (locale === "zh") {
        unlocked = true;
        setLang("zh");
      } else if (!unlocked) {
        setLang("en");
      }
    });
  }

  /* ---------------- generic unlock page (no book name) ------------------ */

  function bootVaultPage() {
    var page = document.getElementById("agb-vault-page");
    if (!page) return;

    var url = (page.getAttribute("data-vault-url") || "").trim();
    var lockView = document.getElementById("agb-lock-view");
    var bookView = document.getElementById("agb-book-view");
    var form = document.getElementById("agb-vault-form");
    var input = document.getElementById("agb-vault-passphrase");
    var message = document.getElementById("agb-vault-message");
    var submit = document.getElementById("agb-vault-submit");
    var cancelBtn = document.getElementById("agb-vault-cancel");
    var progress = createProgress(document.getElementById("agb-vault-progress"));
    if (!lockView || !bookView || !form || !input || !message || !submit) return;

    var busy = false;
    var activeRun = 0;
    var controller = null;

    function setMessage(text, isError) {
      message.textContent = text || "";
      message.classList.toggle("is-error", !!isError);
    }

    function setBusy(on) {
      input.disabled = on;
      submit.hidden = on;
      submit.disabled = on || !url;
      if (cancelBtn) cancelBtn.hidden = !on;
      if (progress) {
        if (on) {
          progress.reset();
          progress.show();
        } else {
          progress.reset();
        }
      }
    }

    function cancelRun() {
      if (!busy) return;
      activeRun++;
      busy = false;
      if (controller) {
        controller.abort();
        controller = null;
      }
      setBusy(false);
      input.value = "";
      setMessage("Unlock canceled.", false);
      input.focus();
    }

    async function beginUnlock(passphrase) {
      busy = true;
      var run = ++activeRun;
      controller = new AbortController();
      setMessage("", false);
      setBusy(true);

      var options = {
        signal: controller.signal,
        onProgress: function (event) {
          if (run === activeRun && progress) progress.update(event);
        }
      };

      try {
        var result = await unlockFromUrl(url, passphrase, options);
        if (run !== activeRun) return;

        startVaultReader(result.pack);
        if (progress) {
          progress.update({
            stage: "render",
            fraction: 1,
            detail: "Chinese edition ready",
            pctText: "100%"
          });
        }
        busy = false;
        controller = null;
        input.value = "";
        setMessage("", false);
        if (progress) progress.reset();
      } catch (err) {
        if (run !== activeRun || (err && err.code === "E_CANCELLED")) return;
        if (progress) progress.reset();
        setMessage(messageFor(err), true);
        input.value = "";
        input.focus();
      } finally {
        if (run === activeRun) {
          busy = false;
          controller = null;
          setBusy(false);
        }
      }
    }

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (busy) return;
      if (!url) {
        setMessage("The encrypted full text is not published yet.", true);
        return;
      }
      var passphrase = input.value;
      if (!passphrase) {
        setMessage("Enter the passphrase.", true);
        input.focus();
        return;
      }
      beginUnlock(passphrase);
    });

    if (cancelBtn) cancelBtn.addEventListener("click", cancelRun);

    function startVaultReader(pack) {
      var structure = pack.structure && pack.structure.sections;
      if (!structure || typeof structure !== "object") {
        throw vaultError("E_BAD_PACK", "This pack has no reading structure.");
      }
      var start = Number(pack.structure.start);
      if (!structure[String(start)]) {
        start = Number(Object.keys(structure)[0]);
      }
      var stack = [start];

      var sectionNo = document.getElementById("agb-section-no");
      var body = document.getElementById("agb-body");
      var choices = document.getElementById("agb-choices");
      var bookTitle = document.getElementById("agb-book-title");
      var backBtn = document.getElementById("agb-back");
      var restartBtn = document.getElementById("agb-restart");
      if (!sectionNo || !body || !choices || !bookTitle) return;

      bookTitle.textContent = pack.book || "";
      lockView.hidden = true;
      bookView.hidden = false;
      input.value = "";
      setMessage("", false);

      function render() {
        var current = stack[stack.length - 1];
        var node = structure[String(current)] || {};
        var blocks = pack.sections[String(current)] || [];
        sectionNo.textContent = current;
        body.innerHTML = blocks.map(function (block) {
          return block.t === "p" ? "<p>" + block.html + "</p>" : "";
        }).join("");
        if (node.prompt) {
          var prompt = document.createElement("div");
          prompt.className = "prompt";
          prompt.textContent = node.prompt;
          body.appendChild(prompt);
        }

        choices.innerHTML = "";
        var edges = node.edges || [];
        if (!edges.length) {
          var end = document.createElement("div");
          end.className = "end";
          end.textContent = "The End";
          choices.appendChild(end);
        } else {
          edges.forEach(function (edge) {
            var btn = document.createElement("button");
            btn.type = "button";
            btn.className = "choice";
            btn.textContent = (edge.label || "Continue") +
              "  \u203a  " + edge.target;
            btn.addEventListener("click", function () {
              stack.push(edge.target);
              render();
              window.scrollTo(0, 0);
            });
            choices.appendChild(btn);
          });
        }
        if (backBtn) backBtn.disabled = stack.length <= 1;
      }

      if (backBtn) {
        backBtn.addEventListener("click", function () {
          if (stack.length > 1) {
            stack.pop();
            render();
            window.scrollTo(0, 0);
          }
        });
      }
      if (restartBtn) {
        restartBtn.addEventListener("click", function () {
          stack = [start];
          render();
          window.scrollTo(0, 0);
        });
      }

      render();
    }
  }

  if (typeof window !== "undefined") {
    window.AGBVault = { decryptVault: decryptVault, unlockFromUrl: unlockFromUrl };
    window.decryptVault = decryptVault;
    window.unlockFromUrl = unlockFromUrl;
  }

  function boot() {
    bootReaderUi();
    bootVaultPage();
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", boot);
    } else {
      boot();
    }
  }
})();
