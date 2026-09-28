/**
 * cipher.js — Logika Kriptografi Murni: XOR Stream Cipher & One-Time Pad
 * 
 * Modul ini TIDAK menyentuh DOM (document) sama sekali.
 * Semua fungsi aman dari exception (tidak throw), selalu mengembalikan objek hasil.
 * Digunakan bersama oleh UI dan Test Runner.
 */

(function () {
  'use strict';

  window.XorApp = window.XorApp || {};

  // =========================================================================
  // 1. Pesan Validasi & Peringatan (Single Source of Truth)
  // =========================================================================
  const MESSAGES = {
    PLAINTEXT_EMPTY: '❌ Error: Plaintext tidak boleh kosong.',
    CIPHERTEXT_EMPTY: '❌ Error: Ciphertext tidak boleh kosong.',
    KEY_EMPTY: '❌ Error: Silakan masukkan kunci.',
    KEY_ONLY_SPACES: '❌ Error: Kunci tidak boleh hanya berisi spasi.',
    UNSUPPORTED_CHAR: (char, pos) =>
      `❌ Error: Karakter "${char}" (posisi ${pos}) tidak didukung. Gunakan karakter ASCII yang dapat dicetak (kode 32–126).`,
    MESSAGE_TOO_LONG: '❌ Error: Pesan terlalu panjang (maksimal 256 karakter).',
    INVALID_HEX:
      '❌ Error: Format ciphertext tidak valid. Gunakan pasangan digit heksadesimal (0–9, A–F), contoh: 08 0A 1D 16.',
    OTP_KEY_TOO_SHORT: (msgLen, keyLen) =>
      `❌ Error: Mode OTP membutuhkan kunci minimal sepanjang pesan (${msgLen} karakter), sedangkan kunci Anda hanya ${keyLen} karakter.`,
    WARN_NON_TEXT_BYTES:
      '⚠ Peringatan: Hasil dekripsi mengandung byte non-teks. Kemungkinan kunci salah atau mode tidak sesuai.',
    WARN_KEY_REPEATED:
      '⚠ Peringatan: Kunci diulang karena lebih pendek dari pesan. Ini bukan OTP dan lebih mudah diserang.',
    UNEXPECTED_ERROR:
      '❌ Error: Terjadi kesalahan tak terduga. Muat ulang halaman dan coba lagi.',
  };

  // =========================================================================
  // 2. Fungsi Pembantu (Helper Functions)
  // =========================================================================

  /**
   * Mengubah angka byte (0–255) menjadi string biner 8-bit (contoh: 01000001)
   */
  function toBinary8(byte) {
    return (byte & 0xff).toString(2).padStart(8, '0');
  }

  /**
   * Mengubah array byte menjadi string heksadesimal huruf besar dipisah spasi
   * Contoh: [8, 10, 29, 22] -> "08 0A 1D 16"
   */
  function toHex(bytes) {
    if (!bytes || !bytes.length) return '';
    return Array.from(bytes)
      .map(b => (b & 0xff).toString(16).toUpperCase().padStart(2, '0'))
      .join(' ');
  }

  /**
   * Mem-parse string heksadesimal menjadi Uint8Array.
   * Menerima format dengan spasi atau tanpa spasi, huruf besar atau kecil.
   * Contoh: "08 0A 1D 16" atau "080a1d16"
   */
  function parseHex(str) {
    if (typeof str !== 'string') {
      return { ok: false, error: MESSAGES.INVALID_HEX };
    }

    // Hapus semua spasi
    const cleaned = str.replace(/\s+/g, '');
    if (cleaned.length === 0) {
      return { ok: false, error: MESSAGES.CIPHERTEXT_EMPTY };
    }

    // Jumlah digit heksadesimal harus genap
    if (cleaned.length % 2 !== 0) {
      return { ok: false, error: MESSAGES.INVALID_HEX };
    }

    // Hanya karakter heksadesimal 0-9, a-f, A-F yang diizinkan
    if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
      return { ok: false, error: MESSAGES.INVALID_HEX };
    }

    const byteLength = cleaned.length / 2;
    const bytes = new Uint8Array(byteLength);

    for (let i = 0; i < byteLength; i++) {
      const hexPair = cleaned.substr(i * 2, 2);
      bytes[i] = parseInt(hexPair, 16);
    }

    return { ok: true, bytes: bytes };
  }

  /**
   * Memvalidasi bahwa setiap karakter dalam string berada dalam rentang ASCII printable (32–126).
   * Posisi karakter dihitung dari 1 untuk pesan error yang ramah pengguna.
   */
  function validateText(str, label = 'Teks') {
    if (typeof str !== 'string') {
      return { ok: false, error: `${label} tidak valid.` };
    }

    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code < 32 || code > 126) {
        let charDisplay = str[i];
        if (typeof str.codePointAt === 'function') {
          try {
            charDisplay = String.fromCodePoint(str.codePointAt(i));
          } catch (e) {
            charDisplay = str[i];
          }
        }
        return {
          ok: false,
          error: MESSAGES.UNSUPPORTED_CHAR(charDisplay, i + 1),
        };
      }
    }

    return { ok: true };
  }

  /**
   * Mengonversi string ASCII printable menjadi Uint8Array
   */
  function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      bytes[i] = str.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Mengonversi Uint8Array menjadi string ASCII.
   * Byte di luar rentang printable (32–126) diganti dengan titik tengah '·' (U+00B7).
   */
  function bytesToString(bytes) {
    let result = '';
    let hasNonText = false;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 32 && b <= 126) {
        result += String.fromCharCode(b);
      } else {
        result += '·';
        hasNonText = true;
      }
    }
    return { text: result, hasNonText: hasNonText };
  }

  /**
   * Menghasilkan keystream sepanjang n byte dari keyBytes berdasarkan mode.
   * - Mode 'stream': key diulang siklik K[i % len(K)]
   * - Mode 'otp': key dipakai apa adanya (hanya n byte pertama)
   */
  function buildKeystream(keyBytes, n, mode) {
    const keystream = new Uint8Array(n);
    const keyLen = keyBytes.length;

    for (let i = 0; i < n; i++) {
      if (mode === 'otp') {
        keystream[i] = keyBytes[i];
      } else {
        // Mode stream: pengulangan siklik
        keystream[i] = keyBytes[i % keyLen];
      }
    }

    return keystream;
  }

  /**
   * Melakukan operasi bitwise XOR antara dua array byte.
   * Panjang hasil mengikuti panjang minimum dari kedua array.
   */
  function xorBytes(a, b) {
    const len = Math.min(a.length, b.length);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }

  /**
   * Menghasilkan kunci acak ASCII printable (kode 32–126, total 95 kemungkinan).
   * Menggunakan crypto.getRandomValues dengan rejection sampling agar bebas dari modulo bias.
   */
  function generateRandomKey(length = 16) {
    const len = Math.max(1, Math.min(length, 256));
    const chars = [];
    const buffer = new Uint8Array(1);

    // 256 - (256 % 95) = 190. Angka di atas atau sama dengan 190 ditolak (rejection sampling).
    const limit = 256 - (256 % 95);

    while (chars.length < len) {
      crypto.getRandomValues(buffer);
      const rand = buffer[0];
      if (rand < limit) {
        // Bebas dari bias modulo
        const charCode = 32 + (rand % 95);
        chars.push(String.fromCharCode(charCode));
      }
    }

    return chars.join('');
  }

  // =========================================================================
  // 3. Logika Enkripsi & Dekripsi
  // =========================================================================

  /**
   * Enkripsi Plaintext dengan Key & Mode tertentu.
   * Rumus: C[i] = P[i] XOR KS[i]
   * 
   * @param {string} plaintext 
   * @param {string} key 
   * @param {'stream'|'otp'} mode 
   * @returns {Object} { ok: true, cipherBytes, cipherHex, steps, warnings, keystreamBytes } | { ok: false, error }
   */
  function encrypt(plaintext, key, mode = 'stream') {
    // 1. Cek string kosong
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      return { ok: false, error: MESSAGES.PLAINTEXT_EMPTY };
    }
    if (typeof key !== 'string' || key.length === 0) {
      return { ok: false, error: MESSAGES.KEY_EMPTY };
    }
    if (key.trim().length === 0) {
      return { ok: false, error: MESSAGES.KEY_ONLY_SPACES };
    }

    // 2. Validasi karakter ASCII 32–126
    const validPlain = validateText(plaintext, 'Plaintext');
    if (!validPlain.ok) return validPlain;

    const validKey = validateText(key, 'Kunci');
    if (!validKey.ok) return validKey;

    // 3. Cek panjang maksimal 256 karakter
    if (plaintext.length > 256) {
      return { ok: false, error: MESSAGES.MESSAGE_TOO_LONG };
    }

    // 4. Validasi aturan mode
    const warnings = [];
    const plainBytes = stringToBytes(plaintext);
    const keyBytes = stringToBytes(key);

    if (mode === 'otp') {
      if (key.length < plaintext.length) {
        return {
          ok: false,
          error: MESSAGES.OTP_KEY_TOO_SHORT(plaintext.length, key.length),
        };
      }
      if (key.length > plaintext.length) {
        warnings.push(
          `Catatan: Kunci lebih panjang dari pesan (${key.length} > ${plaintext.length}). Hanya ${plaintext.length} karakter pertama yang digunakan.`
        );
      }
    } else {
      // Mode stream: jika key lebih pendek, beri peringatan
      if (key.length < plaintext.length) {
        warnings.push(MESSAGES.WARN_KEY_REPEATED);
      }
    }

    // 5. Bangun Keystream & Lakukan Operasi XOR
    const keystreamBytes = buildKeystream(keyBytes, plainBytes.length, mode);
    const cipherBytes = xorBytes(plainBytes, keystreamBytes);

    // 6. Buat data visualisasi langkah per karakter
    const steps = [];
    for (let i = 0; i < plainBytes.length; i++) {
      const pByte = plainBytes[i];
      const kByte = keystreamBytes[i];
      const cByte = cipherBytes[i];

      steps.push({
        index: i + 1,
        inputChar: plaintext[i],
        inputDec: pByte,
        inputBin: toBinary8(pByte),
        keyChar: String.fromCharCode(kByte),
        keyDec: kByte,
        keyBin: toBinary8(kByte),
        xorDec: cByte,
        xorBin: toBinary8(cByte),
        xorHex: cByte.toString(16).toUpperCase().padStart(2, '0'),
      });
    }

    return {
      ok: true,
      cipherBytes: cipherBytes,
      cipherHex: toHex(cipherBytes),
      steps: steps,
      warnings: warnings,
      keystreamBytes: keystreamBytes,
      plainBytes: plainBytes,
      keyBytes: keyBytes,
    };
  }

  /**
   * Dekripsi Ciphertext (hex) dengan Key & Mode tertentu.
   * Rumus: P[i] = C[i] XOR KS[i] (operasi XOR simetris)
   * 
   * @param {string} cipherHex 
   * @param {string} key 
   * @param {'stream'|'otp'} mode 
   * @returns {Object} { ok: true, plainText, plainBytes, steps, warnings, keystreamBytes } | { ok: false, error }
   */
  function decrypt(cipherHex, key, mode = 'stream') {
    // 1. Cek input kosong
    if (typeof cipherHex !== 'string' || cipherHex.trim().length === 0) {
      return { ok: false, error: MESSAGES.CIPHERTEXT_EMPTY };
    }
    if (typeof key !== 'string' || key.length === 0) {
      return { ok: false, error: MESSAGES.KEY_EMPTY };
    }
    if (key.trim().length === 0) {
      return { ok: false, error: MESSAGES.KEY_ONLY_SPACES };
    }

    // 2. Parse heksadesimal
    const parsedHex = parseHex(cipherHex);
    if (!parsedHex.ok) {
      return parsedHex;
    }
    const cipherBytes = parsedHex.bytes;

    // 3. Validasi key ASCII
    const validKey = validateText(key, 'Kunci');
    if (!validKey.ok) return validKey;

    // 4. Cek panjang maksimal
    if (cipherBytes.length > 256) {
      return { ok: false, error: MESSAGES.MESSAGE_TOO_LONG };
    }

    // 5. Validasi aturan mode
    const warnings = [];
    const keyBytes = stringToBytes(key);

    if (mode === 'otp') {
      if (key.length < cipherBytes.length) {
        return {
          ok: false,
          error: MESSAGES.OTP_KEY_TOO_SHORT(cipherBytes.length, key.length),
        };
      }
      if (key.length > cipherBytes.length) {
        warnings.push(
          `Catatan: Kunci lebih panjang dari pesan (${key.length} > ${cipherBytes.length}). Hanya ${cipherBytes.length} karakter pertama yang digunakan.`
        );
      }
    } else {
      if (key.length < cipherBytes.length) {
        warnings.push(MESSAGES.WARN_KEY_REPEATED);
      }
    }

    // 6. Bangun Keystream & Lakukan Operasi XOR (dekripsi identik dengan enkripsi)
    const keystreamBytes = buildKeystream(keyBytes, cipherBytes.length, mode);
    const plainBytes = xorBytes(cipherBytes, keystreamBytes);

    // 7. Konversi byte ke teks & periksa byte non-printable
    const decoded = bytesToString(plainBytes);
    if (decoded.hasNonText) {
      warnings.push(MESSAGES.WARN_NON_TEXT_BYTES);
    }

    // 8. Buat data langkah visualisasi
    const steps = [];
    for (let i = 0; i < cipherBytes.length; i++) {
      const cByte = cipherBytes[i];
      const kByte = keystreamBytes[i];
      const pByte = plainBytes[i];
      const pChar = pByte >= 32 && pByte <= 126 ? String.fromCharCode(pByte) : '·';

      steps.push({
        index: i + 1,
        inputChar: cByte.toString(16).toUpperCase().padStart(2, '0'),
        inputDec: cByte,
        inputBin: toBinary8(cByte),
        keyChar: String.fromCharCode(kByte),
        keyDec: kByte,
        keyBin: toBinary8(kByte),
        xorDec: pByte,
        xorBin: toBinary8(pByte),
        xorHex: pByte.toString(16).toUpperCase().padStart(2, '0'),
        resultChar: pChar,
      });
    }

    return {
      ok: true,
      plainText: decoded.text,
      plainBytes: plainBytes,
      cipherBytes: cipherBytes,
      steps: steps,
      warnings: warnings,
      keystreamBytes: keystreamBytes,
      keyBytes: keyBytes,
    };
  }

  // =========================================================================
  // 4. Publikasikan ke Namespace Global
  // =========================================================================
  window.XorApp.MESSAGES = MESSAGES;
  window.XorApp.cipher = {
    encrypt: encrypt,
    decrypt: decrypt,
    xorBytes: xorBytes,
    buildKeystream: buildKeystream,
    toHex: toHex,
    parseHex: parseHex,
    toBinary8: toBinary8,
    generateRandomKey: generateRandomKey,
    validateText: validateText,
    stringToBytes: stringToBytes,
    bytesToString: bytesToString,
  };
})();
