/**
 * AES-256 cryptographic utilities for PDF decryption (R=6)
 * Uses Web Crypto API — works in browsers, Cloudflare Workers, Deno, Node 18+
 *
 * @author PDFSmaller.com (https://pdfsmaller.com)
 * @license MIT
 *
 * Includes encrypt-side functions (needed for Algorithm 2.B's AES-128-CBC encrypt step)
 * plus decrypt functions for AES-256-CBC/ECB used in PDF object decryption.
 *
 * Implements Algorithm 2.B from ISO 32000-2:2020
 * Verified against mozilla/pdf.js (the reference implementation)
 */

/**
 * Concatenate multiple Uint8Arrays
 */
export function concat(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// ========== SHA Hash Functions (Web Crypto) ==========

export async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

export async function sha384(data) {
  const hash = await crypto.subtle.digest('SHA-384', data);
  return new Uint8Array(hash);
}

export async function sha512(data) {
  const hash = await crypto.subtle.digest('SHA-512', data);
  return new Uint8Array(hash);
}

// ========== AES Encryption (Web Crypto) ==========
// These encrypt functions are needed because Algorithm 2.B uses aes128CbcEncrypt
// even during the decryption password validation flow.

/**
 * AES-128-CBC encrypt (for Algorithm 2.B intermediate step)
 * Strips PKCS#7 padding since input is always block-aligned
 */
export async function aes128CbcEncrypt(data, key, iv) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, cryptoKey, data);
  // Strip PKCS#7 padding block (data is always block-aligned in Algorithm 2.B)
  return new Uint8Array(encrypted).slice(0, data.byteLength);
}

// ========== AES Decryption (Web Crypto) ==========

/**
 * AES-256-CBC decrypt with PKCS#7 padding removal (for per-object decryption)
 * Standard Web Crypto decrypt — handles padding automatically.
 *
 * @param {Uint8Array} data - Ciphertext (must be multiple of 16 bytes)
 * @param {Uint8Array} key - 32-byte AES-256 key
 * @param {Uint8Array} iv - 16-byte initialization vector
 * @returns {Promise<Uint8Array>} - Decrypted plaintext
 */
export async function aes256CbcDecrypt(data, key, iv) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, data);
  return new Uint8Array(decrypted);
}

/**
 * AES-256-CBC decrypt without padding (for UE/OE — exactly 32 bytes, no PKCS#7)
 *
 * Web Crypto mandates PKCS#7 padding and has no "no-padding" option.
 * We use a forged padding block trick:
 *
 * 1. Take the last ciphertext block C_last
 * 2. XOR it with [0x10 * 16] (the PKCS#7 padding for a full block)
 * 3. AES-ECB encrypt the result: C_fake = AES_ENC_K(C_last XOR [0x10*16])
 * 4. Append C_fake to the ciphertext
 * 5. Web Crypto decrypts all blocks and finds valid PKCS#7 padding in C_fake
 * 6. Result = correctly decrypted original bytes (32 bytes for UE/OE)
 *
 * Why this works:
 *   AES_DEC(C_fake) XOR C_last
 *   = AES_DEC(AES_ENC(C_last XOR [0x10*16])) XOR C_last
 *   = (C_last XOR [0x10*16]) XOR C_last
 *   = [0x10*16]  ← valid PKCS#7 padding!
 *
 * @param {Uint8Array} ciphertext - Ciphertext (32 bytes for UE/OE)
 * @param {Uint8Array} key - 32-byte AES-256 key
 * @param {Uint8Array} iv - 16-byte initialization vector
 * @returns {Promise<Uint8Array>} - Decrypted plaintext (same length as ciphertext)
 */
export async function aes256CbcDecryptNoPad(ciphertext, key, iv) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt', 'decrypt']);

  // Get the last ciphertext block
  const lastBlock = ciphertext.slice(ciphertext.length - 16);

  // XOR with PKCS#7 full-block padding value (0x10 = 16)
  const xored = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    xored[i] = lastBlock[i] ^ 0x10;
  }

  // AES-ECB encrypt the XORed block (CBC with zero IV = ECB for single block)
  const zeroIV = new Uint8Array(16);
  const encResult = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: zeroIV }, cryptoKey, xored);
  const cFake = new Uint8Array(encResult).slice(0, 16);

  // Append forged block to ciphertext
  const extended = concat(ciphertext, cFake);

  // Decrypt — Web Crypto will find valid PKCS#7 padding and strip it
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, extended);
  return new Uint8Array(decrypted).slice(0, ciphertext.length);
}

/**
 * AES-256-ECB decrypt a single 16-byte block (for Perms verification)
 * Uses the same forged padding block trick as aes256CbcDecryptNoPad.
 *
 * @param {Uint8Array} block - 16-byte ciphertext block
 * @param {Uint8Array} key - 32-byte AES-256 key
 * @returns {Promise<Uint8Array>} - 16-byte decrypted block
 */
export async function aes256EcbDecryptBlock(block, key) {
  const zeroIV = new Uint8Array(16);
  return aes256CbcDecryptNoPad(block, key, zeroIV);
}

/**
 * Import an AES-256 key for reuse across multiple decrypt operations
 *
 * @param {Uint8Array} key - 32-byte AES-256 key
 * @returns {Promise<CryptoKey>} - Imported CryptoKey for decryption
 */
export async function importAES256DecryptKey(key) {
  return await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt', 'decrypt']);
}

/**
 * AES-256-CBC decrypt using a pre-imported CryptoKey (for per-object bulk decryption)
 * Handles PKCS#7 padding removal automatically.
 *
 * @param {Uint8Array} data - Ciphertext (must be multiple of 16 bytes)
 * @param {CryptoKey} cryptoKey - Pre-imported AES-256 CryptoKey
 * @param {Uint8Array} iv - 16-byte initialization vector
 * @returns {Promise<Uint8Array>} - Decrypted plaintext
 */
export async function aes256CbcDecryptWithKey(data, cryptoKey, iv) {
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, data);
  return new Uint8Array(decrypted);
}

// ========== Algorithm 2.B (ISO 32000-2:2020) ==========

/**
 * Algorithm 2.B — Computing a hash for R=6
 *
 * This is the hardened key derivation function used by PDF 2.0 (AES-256).
 * Iterates SHA-256/384/512 + AES-128-CBC for at least 64 rounds.
 *
 * Note: Algorithm 2.B uses AES-128-CBC *encrypt* (not decrypt) even during
 * the decryption/validation flow. This is by design per the PDF spec.
 *
 * Verified against mozilla/pdf.js (PDF20._hash)
 *
 * @param {Uint8Array} password - UTF-8 password bytes (max 127)
 * @param {Uint8Array} salt - 8-byte salt
 * @param {Uint8Array} userKey - 48-byte U value (for owner ops) or empty
 * @returns {Promise<Uint8Array>} - 32-byte hash
 */
export async function computeHash2B(password, salt, userKey) {
  // Step 1: Initial SHA-256 hash
  const input = concat(password, salt, userKey);
  let K = await sha256(input);

  // Step 2: Iterative loop (minimum 64 rounds)
  let i = 0;
  let E;

  while (true) {
    // Step 2a: K1 = (password + K + userKey) repeated 64 times
    const block = concat(password, K, userKey);
    const K1 = new Uint8Array(block.length * 64);
    for (let j = 0; j < 64; j++) {
      K1.set(block, j * block.length);
    }

    // Step 2b: AES-128-CBC encrypt K1
    // Key = K[0..15], IV = K[16..31]
    const aesKey = K.slice(0, 16);
    const aesIV = K.slice(16, 32);
    E = await aes128CbcEncrypt(K1, aesKey, aesIV);

    // Step 2c: Hash function selection
    // Sum first 16 bytes of E mod 3 (equivalent to 128-bit big-endian mod 3)
    let byteSum = 0;
    for (let j = 0; j < 16; j++) {
      byteSum += E[j];
    }
    const hashSelect = byteSum % 3;

    // Step 2d: Hash E with selected function
    if (hashSelect === 0) {
      K = await sha256(E);
    } else if (hashSelect === 1) {
      K = await sha384(E);
    } else {
      K = await sha512(E);
    }

    // Step 2e: Termination (per pdf.js: while i < 64 || E[-1] > i - 32)
    i++;
    if (i >= 64 && E[E.length - 1] <= i - 32) {
      break;
    }
  }

  return K.slice(0, 32);
}
