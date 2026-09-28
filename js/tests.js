/**
 * tests.js — Daftar Test Case & Test Runner (Tanpa DOM)
 * 
 * Memverifikasi kebenaran fungsi cipher secara otomatis.
 * Semua nilai "Output yang Diharapkan" (expected) di-hardcode sebagai literal string,
 * BUKAN dihitung oleh kode aplikasi saat runtime.
 */

(function () {
  'use strict';

  window.XorApp = window.XorApp || {};

  /**
   * 9 Test Case Wajib sesuai spesifikasi tugas (terverifikasi manual).
   * Nilai expected di-hardcode.
   */
  const TEST_CASES = [
    {
      id: 1,
      description: 'Enkripsi dasar, huruf besar',
      op: 'encrypt',
      mode: 'stream',
      input: 'CODE',
      key: 'KEYS',
      expected: '08 0A 1D 16',
    },
    {
      id: 2,
      description: 'Enkripsi campuran huruf kapital/kecil',
      op: 'encrypt',
      mode: 'otp',
      input: 'Cat',
      key: 'Dog',
      expected: '07 0E 13',
    },
    {
      id: 3,
      description: 'Dekripsi ciphertext heksadesimal',
      op: 'decrypt',
      mode: 'stream',
      input: '18 14 05 15',
      key: 'Rust',
      expected: 'Java',
    },
    {
      id: 4,
      description: 'Key pendek diulang (mode stream)',
      op: 'encrypt',
      mode: 'stream',
      input: 'AAAAAA',
      key: 'xy',
      expected: '39 38 39 38 39 38',
    },
    {
      id: 5,
      description: 'Edge case: plaintext = key → semua nol',
      op: 'encrypt',
      mode: 'stream',
      input: 'Test',
      key: 'Test',
      expected: '00 00 00 00',
    },
    {
      id: 6,
      description: 'Karakter spasi, angka, simbol',
      op: 'encrypt',
      mode: 'otp',
      input: 'Hi 5',
      key: '7Q!z',
      expected: '7F 38 01 4F',
    },
    {
      id: 7,
      description: 'Validasi: key kosong',
      op: 'encrypt',
      mode: 'stream',
      input: 'Hello',
      key: '',
      expected: '❌ Error: Silakan masukkan kunci.',
    },
    {
      id: 8,
      description: 'Validasi: hex tidak valid',
      op: 'decrypt',
      mode: 'stream',
      input: '0G 12',
      key: 'abc',
      expected: '❌ Error: Format ciphertext tidak valid. Gunakan pasangan digit heksadesimal (0–9, A–F), contoh: 08 0A 1D 16.',
    },
    {
      id: 9,
      description: 'Validasi: key OTP terlalu pendek',
      op: 'encrypt',
      mode: 'otp',
      input: 'Halo Dunia',
      key: 'abc',
      expected: '❌ Error: Mode OTP membutuhkan kunci minimal sepanjang pesan (10 karakter), sedangkan kunci Anda hanya 3 karakter.',
    },
  ];

  /**
   * Menjalankan satu test case menggunakan fungsi asli window.XorApp.cipher
   * @param {Object} test 
   * @returns {Object} Hasil pengujian { id, description, op, mode, input, key, expected, actual, passed }
   */
  function executeTest(test) {
    const cipher = window.XorApp.cipher;
    let actual = '';

    if (test.op === 'encrypt') {
      const res = cipher.encrypt(test.input, test.key, test.mode);
      actual = res.ok ? res.cipherHex : res.error;
    } else {
      const res = cipher.decrypt(test.input, test.key, test.mode);
      actual = res.ok ? res.plainText : res.error;
    }

    const passed = actual === test.expected;

    return {
      id: test.id,
      description: test.description,
      op: test.op,
      mode: test.mode,
      input: test.input,
      key: test.key,
      expected: test.expected,
      actual: actual,
      passed: passed,
    };
  }

  /**
   * Menjalankan semua test case yang terdaftar dan mengembalikan ringkasan
   * @returns {Object} { total, passedCount, failedCount, results }
   */
  function runAllTests() {
    const results = TEST_CASES.map(t => executeTest(t));
    const passedCount = results.filter(r => r.passed).length;
    const failedCount = results.length - passedCount;

    return {
      total: results.length,
      passedCount: passedCount,
      failedCount: failedCount,
      allPassed: failedCount === 0,
      results: results,
    };
  }

  /**
   * Menjalankan test case custom yang dimasukkan pengguna
   */
  function runCustomTest(id, description, op, mode, input, key, expected) {
    const test = {
      id: id || 'C1',
      description: description || 'Custom Test',
      op: op,
      mode: mode,
      input: input,
      key: key,
      expected: expected,
    };
    return executeTest(test);
  }

  // =========================================================================
  // Publikasikan ke Namespace Global
  // =========================================================================
  window.XorApp.tests = {
    TEST_CASES: TEST_CASES,
    executeTest: executeTest,
    runAllTests: runAllTests,
    runCustomTest: runCustomTest,
  };
})();
