/* PBKDF2-SHA256 + AES-256-GCM worker for the encrypted-vault client.
 *
 * The main page sends the parsed header fields, the passphrase and the
 * ciphertext. The worker derives the key and decrypts there, so a 600k-round
 * PBKDF2 does not freeze the page. The passphrase is held only in this
 * worker's memory and the worker closes itself as soon as it answers.
 * The decrypted pack is returned as a transferable ArrayBuffer; no storage
 * and no console output happen here.
 */
"use strict";

self.onmessage = function (event) {
  var message = event.data || {};
  if (message.type !== "decrypt") return;

  var id = message.id;
  var passphrase = message.passphrase;
  message.passphrase = null;

  function post(payload, transfer) {
    if (transfer) self.postMessage(payload, transfer);
    else self.postMessage(payload);
  }

  function stop(code) {
    post({ type: "error", id: id, code: code });
    self.close();
  }

  var subtle = self.crypto && self.crypto.subtle;
  if (!subtle || typeof subtle.deriveKey !== "function") {
    stop("E_UNSUPPORTED");
    return;
  }

  post({ type: "stage", id: id, stage: "derive" });

  (async function () {
    var material;
    var key;
    try {
      material = await subtle.importKey(
        "raw",
        new TextEncoder().encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      key = await subtle.deriveKey(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: message.salt,
          iterations: message.iterations
        },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
    } catch (err) {
      stop("E_UNSUPPORTED");
      return;
    }

    post({ type: "stage", id: id, stage: "decrypt" });

    var plain;
    try {
      plain = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: message.iv,
          additionalData: message.aad,
          tagLength: 128
        },
        key,
        message.ciphertext
      );
    } catch (err) {
      // A wrong passphrase and a tampered file are indistinguishable here.
      stop("E_BAD_PASSPHRASE");
      return;
    }

    post({ type: "done", id: id, plain: plain }, [plain]);
    self.close();
  })();
};
