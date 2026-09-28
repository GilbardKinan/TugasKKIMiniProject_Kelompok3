/**
 * attack.js — Logika Kriptanalisis Murni: Serangan Key Reuse (Two-Time Pad) & Crib Dragging
 * 
 * Modul ini TIDAK menyentuh DOM (document) sama sekali.
 * Mendemonstrasikan secara matematis mengapa penggunaan ulang keystream/kunci
 * pada stream cipher / OTP merusak kerahasiaan pesan sepenuhnya.
 */

(function () {
  'use strict';

  window.XorApp = window.XorApp || {};

  /**
   * Menganalisis serangan Two-Time Pad pada dua pesan yang dienkripsi dengan kunci yang sama.
   * 
   * Prinsip Matematika:
   * C1 = M1 ⊕ K
   * C2 = M2 ⊕ K
   * C1 ⊕ C2 = (M1 ⊕ K) ⊕ (M2 ⊕ K) = M1 ⊕ M2 ⊕ (K ⊕ K) = M1 ⊕ M2 ⊕ 0 = M1 ⊕ M2
   * Kunci K lenyap sepenuhnya dari persamaan!
   * 
   * @param {string} msg1 
   * @param {string} msg2 
   * @param {string} key 
   * @returns {Object} Hasil simulasi dan analisis per byte
   */
  function analyzeTwoTimePad(msg1, msg2, key) {
    const cipher = window.XorApp.cipher;
    const MESSAGES = window.XorApp.MESSAGES;

    // 1. Validasi input
    if (!msg1 || msg1.length === 0) {
      return { ok: false, error: '❌ Error: Pesan 1 tidak boleh kosong.' };
    }
    if (!msg2 || msg2.length === 0) {
      return { ok: false, error: '❌ Error: Pesan 2 tidak boleh kosong.' };
    }
    if (!key || key.length === 0) {
      return { ok: false, error: MESSAGES.KEY_EMPTY };
    }
    if (key.trim().length === 0) {
      return { ok: false, error: MESSAGES.KEY_ONLY_SPACES };
    }

    const val1 = cipher.validateText(msg1, 'Pesan 1');
    if (!val1.ok) return val1;

    const val2 = cipher.validateText(msg2, 'Pesan 2');
    if (!val2.ok) return val2;

    const valKey = cipher.validateText(key, 'Kunci');
    if (!valKey.ok) return valKey;

    if (msg1.length > 256 || msg2.length > 256) {
      return { ok: false, error: MESSAGES.MESSAGE_TOO_LONG };
    }

    // 2. Enkripsi kedua pesan dengan kunci yang sama (mode stream agar fleksibel)
    const enc1 = cipher.encrypt(msg1, key, 'stream');
    const enc2 = cipher.encrypt(msg2, key, 'stream');

    if (!enc1.ok) return enc1;
    if (!enc2.ok) return enc2;

    const c1Bytes = enc1.cipherBytes;
    const c2Bytes = enc2.cipherBytes;
    const m1Bytes = cipher.stringToBytes(msg1);
    const m2Bytes = cipher.stringToBytes(msg2);

    // 3. Hitung C1 ⊕ C2 (yang dapat dihitung oleh penyerang dari penyadapan)
    const c1XorC2 = cipher.xorBytes(c1Bytes, c2Bytes);

    // 4. Hitung M1 ⊕ M2 (bukti matematis bahwa hasilnya identik)
    const m1XorM2 = cipher.xorBytes(m1Bytes, m2Bytes);

    // 5. Verifikasi apakah C1 ⊕ C2 identik dengan M1 ⊕ M2
    let isIdentical = c1XorC2.length === m1XorM2.length;
    if (isIdentical) {
      for (let i = 0; i < c1XorC2.length; i++) {
        if (c1XorC2[i] !== m1XorM2[i]) {
          isIdentical = false;
          break;
        }
      }
    }

    // 6. Analisis byte per byte: cari byte 00 (posisi karakter kembar)
    const minLen = Math.min(msg1.length, msg2.length);
    const byteAnalysis = [];
    const identicalPositions = []; // Indeks 0-based yang menghasilkan 0x00

    for (let i = 0; i < minLen; i++) {
      const bC1 = c1Bytes[i];
      const bC2 = c2Bytes[i];
      const xorByte = c1XorC2[i];
      const isZero = xorByte === 0;

      if (isZero) {
        identicalPositions.push(i);
      }

      byteAnalysis.push({
        index: i + 1,
        m1Char: msg1[i],
        m2Char: msg2[i],
        c1Hex: bC1.toString(16).toUpperCase().padStart(2, '0'),
        c2Hex: bC2.toString(16).toUpperCase().padStart(2, '0'),
        xorHex: xorByte.toString(16).toUpperCase().padStart(2, '0'),
        xorBin: cipher.toBinary8(xorByte),
        isZero: isZero,
        charsMatch: msg1[i] === msg2[i],
      });
    }

    let lengthWarning = null;
    if (msg1.length !== msg2.length) {
      lengthWarning = `Catatan: Panjang pesan berbeda (${msg1.length} vs ${msg2.length}). Operasi XOR dianalisis hingga panjang terpendek (${minLen} karakter).`;
    }

    return {
      ok: true,
      msg1: msg1,
      msg2: msg2,
      key: key,
      c1Hex: enc1.cipherHex,
      c2Hex: enc2.cipherHex,
      c1Bytes: c1Bytes,
      c2Bytes: c2Bytes,
      c1XorC2Bytes: c1XorC2,
      c1XorC2Hex: cipher.toHex(c1XorC2),
      m1XorM2Hex: cipher.toHex(m1XorM2),
      isIdentical: isIdentical,
      identicalPositions: identicalPositions,
      byteAnalysis: byteAnalysis,
      lengthWarning: lengthWarning,
    };
  }

  /**
   * Menjalankan teknik Crib Dragging:
   * Menggeser tebakan kata (crib) di sepanjang hasil C1 ⊕ C2.
   * Untuk setiap posisi i:
   * Fragmen M2 = (C1 ⊕ C2)[i .. i+k] ⊕ crib
   * 
   * Jika fragmen menghasilkan teks ASCII yang terbaca (printable),
   * kemungkinan besar tebakan berada pada posisi yang tepat!
   * 
   * @param {Uint8Array} c1XorC2Bytes 
   * @param {string} crib 
   * @returns {Object} Daftar kandidat pergeseran
   */
  function cribDrag(c1XorC2Bytes, crib) {
    const cipher = window.XorApp.cipher;
    if (!c1XorC2Bytes || c1XorC2Bytes.length === 0) {
      return { ok: false, error: 'Belum ada data C1 ⊕ C2.' };
    }
    if (!crib || crib.length === 0) {
      return { ok: false, error: 'Silakan masukkan tebakan kata (crib).' };
    }

    const valCrib = cipher.validateText(crib, 'Tebakan kata');
    if (!valCrib.ok) return valCrib;

    if (crib.length > c1XorC2Bytes.length) {
      return {
        ok: false,
        error: `Tebakan kata (${crib.length} karakter) lebih panjang dari ciphertext (${c1XorC2Bytes.length} karakter).`,
      };
    }

    const cribBytes = cipher.stringToBytes(crib);
    const maxOffset = c1XorC2Bytes.length - crib.length;
    const candidates = [];

    for (let offset = 0; offset <= maxOffset; offset++) {
      let isFullyPrintable = true;
      let fragment = '';
      const hexList = [];

      for (let j = 0; j < crib.length; j++) {
        const xorVal = c1XorC2Bytes[offset + j] ^ cribBytes[j];
        hexList.push(xorVal.toString(16).toUpperCase().padStart(2, '0'));

        if (xorVal >= 32 && xorVal <= 126) {
          fragment += String.fromCharCode(xorVal);
        } else {
          fragment += '·';
          isFullyPrintable = false;
        }
      }

      candidates.push({
        position: offset + 1, // 1-indexed untuk tampilan
        offset: offset,
        crib: crib,
        fragment: fragment,
        fragmentHex: hexList.join(' '),
        isPrintable: isFullyPrintable,
      });
    }

    return {
      ok: true,
      crib: crib,
      totalPositions: candidates.length,
      candidates: candidates,
    };
  }

  /**
   * Menghitung pemulihan Pesan 2 jika Pesan 1 diketahui secara utuh:
   * M2 = (C1 ⊕ C2) ⊕ M1
   * 
   * @param {Uint8Array} c1XorC2Bytes 
   * @param {string} knownM1 
   * @returns {Object} Teks hasil pemulihan M2
   */
  function recoverMessage2(c1XorC2Bytes, knownM1) {
    const cipher = window.XorApp.cipher;
    const m1Bytes = cipher.stringToBytes(knownM1);
    const recoveredBytes = cipher.xorBytes(c1XorC2Bytes, m1Bytes);
    const decoded = cipher.bytesToString(recoveredBytes);

    return {
      ok: true,
      recoveredText: decoded.text,
      recoveredHex: cipher.toHex(recoveredBytes),
      hasNonText: decoded.hasNonText,
    };
  }

  /**
   * Simulasi Kontras: Menggunakan DUA kunci berbeda (One-Time Pad yang benar).
   * Menunjukkan bahwa jika K1 ≠ K2, maka C1 ⊕ C2 ≠ M1 ⊕ M2,
   * sehingga penyerang tidak dapat menghilangkan kunci dan serangan gagal total!
   * 
   * @param {string} msg1 
   * @param {string} msg2 
   * @returns {Object}
   */
  function simulateDifferentKeys(msg1, msg2) {
    const cipher = window.XorApp.cipher;
    const maxLen = Math.max(msg1.length, msg2.length);

    // Buat dua kunci independen sejati
    const key1 = cipher.generateRandomKey(maxLen);
    const key2 = cipher.generateRandomKey(maxLen);

    const enc1 = cipher.encrypt(msg1, key1, 'otp');
    const enc2 = cipher.encrypt(msg2, key2, 'otp');

    const c1XorC2 = cipher.xorBytes(enc1.cipherBytes, enc2.cipherBytes);
    const m1Bytes = cipher.stringToBytes(msg1);
    const m2Bytes = cipher.stringToBytes(msg2);
    const m1XorM2 = cipher.xorBytes(m1Bytes, m2Bytes);

    // Periksa kesamaan
    let isIdentical = c1XorC2.length === m1XorM2.length;
    if (isIdentical) {
      for (let i = 0; i < c1XorC2.length; i++) {
        if (c1XorC2[i] !== m1XorM2[i]) {
          isIdentical = false;
          break;
        }
      }
    }

    return {
      ok: true,
      key1: key1,
      key2: key2,
      c1Hex: enc1.cipherHex,
      c2Hex: enc2.cipherHex,
      c1XorC2Hex: cipher.toHex(c1XorC2),
      m1XorM2Hex: cipher.toHex(m1XorM2),
      isIdentical: isIdentical, // Pasti false karena K1 ≠ K2
    };
  }

  // =========================================================================
  // Publikasikan ke Namespace Global
  // =========================================================================
  window.XorApp.attack = {
    analyzeTwoTimePad: analyzeTwoTimePad,
    cribDrag: cribDrag,
    recoverMessage2: recoverMessage2,
    simulateDifferentKeys: simulateDifferentKeys,
  };
})();
