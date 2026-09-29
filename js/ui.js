/**
 * ui.js — Pengendali Antarmuka (DOM Event Handlers & Rendering)
 * 
 * Bertanggung jawab atas seluruh interaksi DOM:
 * - Form enkripsi & dekripsi
 * - Visualisasi bitwise XOR per karakter
 * - Test suite runner & rendering tabel
 * - Demo serangan Two-Time Pad & Crib Dragging
 * - Pemeriksa kepatuhan One-Time Pad (Live OTP Inspector)
 * 
 * Aturan Keamanan DOM:
 * Data pengguna hanya boleh masuk lewat textContent atau createElement (NO innerHTML dengan data pengguna).
 */

(function () {
  'use strict';

  // Pastikan namespace dan modul logika tersedia
  const cipher = window.XorApp?.cipher;
  const attack = window.XorApp?.attack;
  const tests = window.XorApp?.tests;
  const MESSAGES = window.XorApp?.MESSAGES;

  if (!cipher || !attack || !tests) {
    console.error('Dependensi XorApp belum termuat.');
    return;
  }

  // =========================================================================
  // State Aplikasi (Tersimpan di Memori Saja)
  // =========================================================================
  const state = {
    encMode: 'stream',      // 'stream' | 'otp'
    decMode: 'stream',      // 'stream' | 'otp'
    isKeyRandomGenerated: false, // Flag pelacak apakah kunci dibuat via tombol acak
    usedKeysMap: new Map(), // Menyimpan key -> Set(plaintext) dalam sesi untuk cek reuse
    currentSteps: [],       // Langkah visualisasi aktif
    attackData: null,       // Data hasil analisis serangan terakhir
  };

  // =========================================================================
  // DOM Elements Cache
  // =========================================================================
  const dom = {
    // Enkripsi
    encPlain: document.getElementById('enc-plaintext'),
    encKey: document.getElementById('enc-key'),
    encPlainCounter: document.getElementById('enc-plain-counter'),
    encKeyCounter: document.getElementById('enc-key-counter'),
    encModeStream: document.getElementById('enc-mode-stream'),
    encModeOtp: document.getElementById('enc-mode-otp'),
    btnEncrypt: document.getElementById('btn-encrypt'),
    btnRandomKey: document.getElementById('btn-random-key'),
    encAlert: document.getElementById('enc-alert'),
    encOutputCard: document.getElementById('enc-output-card'),
    encOutputVal: document.getElementById('enc-output-val'),
    btnCopyCipher: document.getElementById('btn-copy-cipher'),
    btnSendToDecrypt: document.getElementById('btn-send-to-decrypt'),
    metricMsgLen: document.getElementById('metric-msg-len'),
    metricKeyLen: document.getElementById('metric-key-len'),
    metricKsLen: document.getElementById('metric-ks-len'),

    // Dekripsi
    decCipher: document.getElementById('dec-ciphertext'),
    decKey: document.getElementById('dec-key'),
    decKeyCounter: document.getElementById('dec-key-counter'),
    decModeStream: document.getElementById('dec-mode-stream'),
    decModeOtp: document.getElementById('dec-mode-otp'),
    btnDecrypt: document.getElementById('btn-decrypt'),
    decAlert: document.getElementById('dec-alert'),
    decOutputCard: document.getElementById('dec-output-card'),
    decOutputVal: document.getElementById('dec-output-val'),
    btnCopyPlain: document.getElementById('btn-copy-plain'),

    // Visualisasi
    visSourceLabel: document.getElementById('vis-source-label'),
    visStepSummary: document.getElementById('vis-step-summary'),
    visStepsTbody: document.getElementById('vis-steps-tbody'),
    btnVisNext: document.getElementById('btn-vis-next'),
    btnVisAll: document.getElementById('btn-vis-all'),

    // Test Cases
    btnRunAllTests: document.getElementById('btn-run-all-tests'),
    testSummaryScore: document.getElementById('test-summary-score'),
    testCasesTbody: document.getElementById('test-cases-tbody'),
    customTestOp: document.getElementById('custom-test-op'),
    customTestMode: document.getElementById('custom-test-mode'),
    customTestInput: document.getElementById('custom-test-input'),
    customTestKey: document.getElementById('custom-test-key'),
    customTestExpected: document.getElementById('custom-test-expected'),
    btnRunCustomTest: document.getElementById('btn-run-custom-test'),
    customTestResult: document.getElementById('custom-test-result'),

    // Serangan Key Reuse
    attackM1: document.getElementById('attack-m1'),
    attackM2: document.getElementById('attack-m2'),
    attackKey: document.getElementById('attack-key'),
    btnAttackRandomKey: document.getElementById('btn-attack-random-key'),
    btnRunAttack: document.getElementById('btn-run-attack'),
    btnToggleDiffKey: document.getElementById('btn-toggle-diff-key'),
    attackAlert: document.getElementById('attack-alert'),
    attackC1Hex: document.getElementById('attack-c1-hex'),
    attackC2Hex: document.getElementById('attack-c2-hex'),
    attackC1xC2Hex: document.getElementById('attack-c1xc2-hex'),
    attackM1xM2Hex: document.getElementById('attack-m1xm2-hex'),
    attackIdenticalIndicator: document.getElementById('attack-identical-indicator'),
    attackByteTbody: document.getElementById('attack-byte-tbody'),
    cribInput: document.getElementById('crib-input'),
    btnDragCrib: document.getElementById('btn-drag-crib'),
    cribResultsTbody: document.getElementById('crib-results-tbody'),
    btnRevealFullM2: document.getElementById('btn-reveal-full-m2'),
    fullM2Card: document.getElementById('full-m2-card'),
    fullM2Val: document.getElementById('full-m2-val'),

    // OTP Checker
    otpCheckLen: document.getElementById('otp-check-len'),
    otpNoteLen: document.getElementById('otp-note-len'),
    otpCheckRnd: document.getElementById('otp-check-rnd'),
    otpNoteRnd: document.getElementById('otp-note-rnd'),
    otpCheckReuse: document.getElementById('otp-check-reuse'),
    otpNoteReuse: document.getElementById('otp-note-reuse'),
  };

  // =========================================================================
  // Helper UI: Notifikasi & Clipboard
  // =========================================================================

  function showAlert(alertEl, message, isWarning = false) {
    if (!alertEl) return;
    alertEl.textContent = message;
    alertEl.classList.remove('hidden');
    if (isWarning) {
      alertEl.classList.add('alert-warn');
    } else {
      alertEl.classList.remove('alert-warn');
    }
  }

  function hideAlert(alertEl) {
    if (!alertEl) return;
    alertEl.textContent = '';
    alertEl.classList.add('hidden');
    alertEl.classList.remove('alert-warn');
  }

  function copyToClipboard(text, buttonEl) {
    if (!text) return;
    const originalText = buttonEl ? buttonEl.textContent : '';

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => {
        if (buttonEl) {
          buttonEl.textContent = '✓ Tersalin!';
          setTimeout(() => { buttonEl.textContent = originalText; }, 1800);
        }
      }).catch(() => fallbackCopy(text, buttonEl, originalText));
    } else {
      fallbackCopy(text, buttonEl, originalText);
    }
  }

  function fallbackCopy(text, buttonEl, originalText) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      document.execCommand('copy');
      if (buttonEl) {
        buttonEl.textContent = '✓ Tersalin!';
        setTimeout(() => { buttonEl.textContent = originalText; }, 1800);
      }
    } catch (err) {
      if (buttonEl) {
        buttonEl.textContent = 'Gagal';
        setTimeout(() => { buttonEl.textContent = originalText; }, 1800);
      }
    }
    document.body.removeChild(textArea);
  }

  // =========================================================================
  // 1. Modul Enkripsi
  // =========================================================================

  function updateEncCounters() {
    const plainLen = dom.encPlain ? dom.encPlain.value.length : 0;
    const keyLen = dom.encKey ? dom.encKey.value.length : 0;
    if (dom.encPlainCounter) dom.encPlainCounter.textContent = `${plainLen} / 256`;
    if (dom.encKeyCounter) dom.encKeyCounter.textContent = `${keyLen} karakter`;
    updateOtpChecker();
  }

  function setEncMode(mode) {
    state.encMode = mode;
    if (mode === 'stream') {
      dom.encModeStream.classList.add('active');
      dom.encModeStream.setAttribute('aria-checked', 'true');
      dom.encModeOtp.classList.remove('active');
      dom.encModeOtp.setAttribute('aria-checked', 'false');
    } else {
      dom.encModeOtp.classList.add('active');
      dom.encModeOtp.setAttribute('aria-checked', 'true');
      dom.encModeStream.classList.remove('active');
      dom.encModeStream.setAttribute('aria-checked', 'false');
    }
    hideAlert(dom.encAlert);
    updateOtpChecker();
  }

  function handleRandomKey() {
    try {
      const plainLen = dom.encPlain.value.length;
      const targetLen = plainLen > 0 ? plainLen : 16;
      const newKey = cipher.generateRandomKey(targetLen);
      dom.encKey.value = newKey;
      state.isKeyRandomGenerated = true;
      dom.encKey.classList.remove('is-invalid');
      updateEncCounters();
      hideAlert(dom.encAlert);
    } catch (e) {
      showAlert(dom.encAlert, MESSAGES.UNEXPECTED_ERROR);
    }
  }

  function handleEncrypt() {
    hideAlert(dom.encAlert);
    dom.encPlain.classList.remove('is-invalid');
    dom.encKey.classList.remove('is-invalid');

    try {
      const plaintext = dom.encPlain.value;
      const key = dom.encKey.value;
      const result = cipher.encrypt(plaintext, key, state.encMode);

      if (!result.ok) {
        showAlert(dom.encAlert, result.error);
        if (result.error.includes('Plaintext') || result.error.includes('Pesan')) {
          dom.encPlain.classList.add('is-invalid');
          dom.encPlain.setAttribute('aria-invalid', 'true');
        } else {
          dom.encKey.classList.add('is-invalid');
          dom.encKey.setAttribute('aria-invalid', 'true');
        }
        return;
      }

      // Tampilkan hasil
      dom.encOutputVal.textContent = result.cipherHex;
      dom.metricMsgLen.textContent = `${plaintext.length} byte`;
      dom.metricKeyLen.textContent = `${key.length} byte`;
      dom.metricKsLen.textContent = `${result.keystreamBytes.length} byte`;
      dom.encOutputCard.classList.remove('hidden');

      // Tampilkan peringatan jika ada (misal pengulangan kunci)
      if (result.warnings && result.warnings.length > 0) {
        showAlert(dom.encAlert, result.warnings.join(' | '), true);
      }

      // Catat penggunaan key di memori untuk deteksi reuse
      if (!state.usedKeysMap.has(key)) {
        state.usedKeysMap.set(key, new Set());
      }
      state.usedKeysMap.get(key).add(plaintext);

      // Perbarui Visualisasi
      dom.visSourceLabel.textContent = 'Sumber: Enkripsi';
      renderVisualizationSteps(result.steps);

      // Perbarui OTP Checker
      updateOtpChecker();

    } catch (err) {
      showAlert(dom.encAlert, MESSAGES.UNEXPECTED_ERROR);
    }
  }

  function handleSendToDecrypt() {
    const cipherHex = dom.encOutputVal.textContent;
    const key = dom.encKey.value;
    if (!cipherHex || cipherHex === '-') return;

    dom.decCipher.value = cipherHex;
    dom.decKey.value = key;
    setDecMode(state.encMode);
    hideAlert(dom.decAlert);

    // Scroll ke bagian dekripsi
    const decSection = document.getElementById('dekripsi');
    if (decSection) {
      decSection.scrollIntoView({ behavior: 'smooth' });
    }
  }

  // =========================================================================
  // 2. Modul Dekripsi
  // =========================================================================

  function setDecMode(mode) {
    state.decMode = mode;
    if (mode === 'stream') {
      dom.decModeStream.classList.add('active');
      dom.decModeStream.setAttribute('aria-checked', 'true');
      dom.decModeOtp.classList.remove('active');
      dom.decModeOtp.setAttribute('aria-checked', 'false');
    } else {
      dom.decModeOtp.classList.add('active');
      dom.decModeOtp.setAttribute('aria-checked', 'true');
      dom.decModeStream.classList.remove('active');
      dom.decModeStream.setAttribute('aria-checked', 'false');
    }
    hideAlert(dom.decAlert);
  }

  function handleDecrypt() {
    hideAlert(dom.decAlert);
    dom.decCipher.classList.remove('is-invalid');
    dom.decKey.classList.remove('is-invalid');

    try {
      const cipherHex = dom.decCipher.value;
      const key = dom.decKey.value;
      const result = cipher.decrypt(cipherHex, key, state.decMode);

      if (!result.ok) {
        showAlert(dom.decAlert, result.error);
        if (result.error.includes('Ciphertext') || result.error.includes('heksadesimal')) {
          dom.decCipher.classList.add('is-invalid');
          dom.decCipher.setAttribute('aria-invalid', 'true');
        } else {
          dom.decKey.classList.add('is-invalid');
          dom.decKey.setAttribute('aria-invalid', 'true');
        }
        return;
      }

      // Tampilkan hasil dekripsi
      dom.decOutputVal.textContent = result.plainText;
      dom.decOutputCard.classList.remove('hidden');

      // Tampilkan peringatan jika byte non-printable
      if (result.warnings && result.warnings.length > 0) {
        showAlert(dom.decAlert, result.warnings.join(' | '), true);
      }

      // Perbarui Visualisasi
      dom.visSourceLabel.textContent = 'Sumber: Dekripsi';
      renderVisualizationSteps(result.steps);

    } catch (err) {
      showAlert(dom.decAlert, MESSAGES.UNEXPECTED_ERROR);
    }
  }

  // =========================================================================
  // 3. Modul Visualisasi Operasi Bitwise XOR
  // =========================================================================

  /**
   * Merender format biner 8-bit dengan bit '1' diberi warna aksen Gold Leaf
   * dan bit '0' diredam dengan Bone Gray.
   * Aman dari XSS karena dibangun per elemen DOM.
   */
  function createColoredBinarySpan(binaryStr) {
    const container = document.createElement('span');
    container.className = 'mono';

    for (let i = 0; i < binaryStr.length; i++) {
      const bitSpan = document.createElement('span');
      const char = binaryStr[i];
      bitSpan.textContent = char;
      if (char === '1') {
        bitSpan.className = 'bit-1';
      } else {
        bitSpan.className = 'bit-0';
      }
      container.appendChild(bitSpan);
    }

    return container;
  }

  function updateVisSummary(currentCount, totalCount) {
    if (!dom.visStepSummary) return;
    if (!totalCount) {
      dom.visStepSummary.textContent = 'Tidak ada langkah untuk ditampilkan';
    } else if (totalCount === 1) {
      dom.visStepSummary.textContent = 'Menampilkan 1 langkah karakter';
    } else if (currentCount >= totalCount) {
      dom.visStepSummary.textContent = `Menampilkan semua (${totalCount} langkah karakter)`;
    } else {
      dom.visStepSummary.textContent = `Menampilkan langkah ${currentCount} dari ${totalCount} karakter`;
    }
  }

  function renderVisualizationSteps(steps) {
    if (!steps || !steps.length) {
      dom.visStepsTbody.innerHTML = '';
      updateVisSummary(0, 0);
      return;
    }
    state.currentSteps = steps;

    dom.visStepsTbody.innerHTML = '';

    steps.forEach((st, idx) => {
      const tr = document.createElement('tr');
      tr.className = 'step-row';

      // Langkah pertama langsung ditampilkan, langkah berikutnya disembunyikan untuk inspeksi manual step-by-step
      if (idx === 0) {
        tr.style.display = '';
        tr.classList.add('step-highlight');
      } else {
        tr.style.display = 'none';
      }

      // 1. Index
      const tdIdx = document.createElement('td');
      tdIdx.textContent = st.index;
      tr.appendChild(tdIdx);

      // 2. Input Char
      const tdInChar = document.createElement('td');
      tdInChar.textContent = st.inputChar;
      tdInChar.style.color = 'var(--color-muted-cobalt)';
      tr.appendChild(tdInChar);

      // 3. ASCII Dec
      const tdInDec = document.createElement('td');
      tdInDec.textContent = st.inputDec;
      tr.appendChild(tdInDec);

      // 4. Biner Input
      const tdInBin = document.createElement('td');
      tdInBin.appendChild(createColoredBinarySpan(st.inputBin));
      tr.appendChild(tdInBin);

      // 5. Key Char
      const tdKeyChar = document.createElement('td');
      tdKeyChar.textContent = st.keyChar;
      tr.appendChild(tdKeyChar);

      // 6. Biner Key
      const tdKeyBin = document.createElement('td');
      tdKeyBin.appendChild(createColoredBinarySpan(st.keyBin));
      tr.appendChild(tdKeyBin);

      // 7. Hasil XOR (Biner)
      const tdXorBin = document.createElement('td');
      tdXorBin.appendChild(createColoredBinarySpan(st.xorBin));
      tr.appendChild(tdXorBin);

      // 8. Hex
      const tdHex = document.createElement('td');
      tdHex.textContent = st.xorHex;
      tdHex.style.color = 'var(--color-gold-leaf)';
      tdHex.style.fontWeight = '600';
      tr.appendChild(tdHex);

      dom.visStepsTbody.appendChild(tr);
    });

    updateVisSummary(1, steps.length);

    if (dom.btnVisNext) {
      dom.btnVisNext.textContent = 'Langkah berikutnya';
    }
  }

  function nextStepManual() {
    const rows = dom.visStepsTbody.querySelectorAll('tr');
    if (!rows.length) return;

    // Cari baris pertama yang masih tersembunyi
    let nextIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].style.display === 'none') {
        nextIndex = i;
        break;
      }
    }

    if (nextIndex !== -1) {
      // Tampilkan baris berikutnya
      rows.forEach(r => r.classList.remove('step-highlight'));
      rows[nextIndex].style.display = '';
      rows[nextIndex].classList.add('step-highlight');
      rows[nextIndex].scrollIntoView({ block: 'nearest', behavior: 'smooth' });

      const isNowAllShown = (nextIndex === rows.length - 1);
      updateVisSummary(nextIndex + 1, rows.length);

      if (dom.btnVisNext) {
        dom.btnVisNext.textContent = isNowAllShown ? 'Ulangi dari awal' : 'Langkah berikutnya';
      }
    } else {
      // Jika semua sudah tampil, klik berikutnya akan mengulang dari langkah 1
      rows.forEach((r, idx) => {
        if (idx === 0) {
          r.style.display = '';
          r.classList.add('step-highlight');
        } else {
          r.style.display = 'none';
          r.classList.remove('step-highlight');
        }
      });

      const scrollContainer = dom.visStepsTbody.closest('.table-scroll-container');
      if (scrollContainer) {
        scrollContainer.scrollTop = 0;
      }

      updateVisSummary(1, rows.length);

      if (dom.btnVisNext) {
        dom.btnVisNext.textContent = 'Langkah berikutnya';
      }
    }
  }

  function showAllSteps() {
    const rows = dom.visStepsTbody.querySelectorAll('tr');
    if (!rows.length) return;

    rows.forEach(r => {
      r.style.display = '';
      r.classList.remove('step-highlight');
    });

    updateVisSummary(rows.length, rows.length);

    if (dom.btnVisNext) {
      dom.btnVisNext.textContent = rows.length > 1 ? 'Ulangi dari awal' : 'Langkah berikutnya';
    }
  }

  // =========================================================================
  // 4. Modul Test Cases Runner
  // =========================================================================

  function runAndRenderTests() {
    try {
      const suite = tests.runAllTests();
      dom.testCasesTbody.innerHTML = '';

      dom.testSummaryScore.textContent = `${suite.passedCount} / ${suite.total} Lulus (PASS)`;
      if (suite.allPassed) {
        dom.testSummaryScore.style.color = 'var(--color-status-pass)';
      } else {
        dom.testSummaryScore.style.color = 'var(--color-status-error)';
      }

      suite.results.forEach(res => {
        const tr = document.createElement('tr');

        // ID
        const tdId = document.createElement('td');
        tdId.textContent = res.id;
        tr.appendChild(tdId);

        // Deskripsi
        const tdDesc = document.createElement('td');
        tdDesc.textContent = res.description;
        tr.appendChild(tdDesc);

        // Operasi & Mode
        const tdOp = document.createElement('td');
        tdOp.textContent = `${res.op.toUpperCase()} (${res.mode})`;
        tdOp.style.color = 'var(--color-muted-cobalt)';
        tr.appendChild(tdOp);

        // Input & Key
        const tdInput = document.createElement('td');
        const inputDisplay = res.input ? `"${res.input}"` : '(kosong)';
        const keyDisplay = res.key ? `"${res.key}"` : '(kosong)';
        tdInput.textContent = `Teks: ${inputDisplay}, Key: ${keyDisplay}`;
        tr.appendChild(tdInput);

        // Output Anda
        const tdActual = document.createElement('td');
        tdActual.textContent = res.actual;
        tdActual.style.color = res.passed ? 'var(--color-warm-off-white)' : 'var(--color-status-error)';
        tr.appendChild(tdActual);

        // Output Diharapkan
        const tdExp = document.createElement('td');
        tdExp.textContent = res.expected;
        tdExp.style.color = 'var(--color-pale-stone)';
        tr.appendChild(tdExp);

        // Status
        const tdStatus = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = `status-badge ${res.passed ? 'status-pass' : 'status-fail'}`;
        badge.textContent = res.passed ? '✓ PASS' : '✗ FAIL';
        tdStatus.appendChild(badge);
        tr.appendChild(tdStatus);

        dom.testCasesTbody.appendChild(tr);
      });

    } catch (err) {
      dom.testSummaryScore.textContent = '❌ Gagal menjalankan pengujian otomatis.';
    }
  }

  function handleRunCustomTest() {
    const op = dom.customTestOp.value;
    const mode = dom.customTestMode.value;
    const input = dom.customTestInput.value;
    const key = dom.customTestKey.value;
    const expected = dom.customTestExpected.value;

    if (!expected) {
      dom.customTestResult.textContent = 'Silakan isi output yang diharapkan.';
      dom.customTestResult.style.color = 'var(--color-status-warn)';
      return;
    }

    const res = tests.runCustomTest('Custom', 'Pengujian Pengguna', op, mode, input, key, expected);
    dom.customTestResult.textContent = res.passed 
      ? `✓ PASS (Hasil: "${res.actual}")` 
      : `✗ FAIL (Hasil Anda: "${res.actual}" ≠ Harapan: "${res.expected}")`;
    dom.customTestResult.style.color = res.passed ? 'var(--color-status-pass)' : 'var(--color-status-error)';
  }

  // =========================================================================
  // 5. Modul Serangan Key Reuse (Two-Time Pad)
  // =========================================================================

  function runAttackAnalysis() {
    hideAlert(dom.attackAlert);
    dom.fullM2Card.classList.add('hidden');

    try {
      const m1 = dom.attackM1.value;
      const m2 = dom.attackM2.value;
      const key = dom.attackKey.value;

      const result = attack.analyzeTwoTimePad(m1, m2, key);
      if (!result.ok) {
        showAlert(dom.attackAlert, result.error);
        return;
      }

      state.attackData = result;

      // Update tampilan Langkah 1 & 2
      dom.attackC1Hex.textContent = result.c1Hex;
      dom.attackC2Hex.textContent = result.c2Hex;

      // Update tampilan Langkah 3 & 4
      dom.attackC1xC2Hex.textContent = result.c1XorC2Hex;
      dom.attackM1xM2Hex.textContent = result.m1XorM2Hex;

      if (result.isIdentical) {
        dom.attackIdenticalIndicator.innerHTML = `
          <span>C1 ⊕ C2 = M1 ⊕ M2</span>
          <span style="color: var(--color-status-pass); font-weight: 600;">✓ IDENTIK — KUNCI HILANG SEPENUHNYA</span>
        `;
      } else {
        dom.attackIdenticalIndicator.innerHTML = `
          <span>C1 ⊕ C2 ≠ M1 ⊕ M2</span>
          <span style="color: var(--color-status-error); font-weight: 600;">✗ TIDAK IDENTIK</span>
        `;
      }

      // Update Tabel Byte Kebocoran (Langkah 5)
      dom.attackByteTbody.innerHTML = '';
      result.byteAnalysis.forEach(row => {
        const tr = document.createElement('tr');

        // Posisi
        const tdPos = document.createElement('td');
        tdPos.textContent = row.index;
        tr.appendChild(tdPos);

        // M1 Char
        const tdM1 = document.createElement('td');
        tdM1.textContent = row.m1Char === ' ' ? '(spasi)' : row.m1Char;
        tr.appendChild(tdM1);

        // M2 Char
        const tdM2 = document.createElement('td');
        tdM2.textContent = row.m2Char === ' ' ? '(spasi)' : row.m2Char;
        tr.appendChild(tdM2);

        // C1 Hex
        const tdC1 = document.createElement('td');
        tdC1.textContent = row.c1Hex;
        tr.appendChild(tdC1);

        // C2 Hex
        const tdC2 = document.createElement('td');
        tdC2.textContent = row.c2Hex;
        tr.appendChild(tdC2);

        // XOR Hex
        const tdXor = document.createElement('td');
        if (row.isZero) {
          const spanZero = document.createElement('span');
          spanZero.className = 'byte-zero-highlight';
          spanZero.textContent = row.xorHex;
          tdXor.appendChild(spanZero);
        } else {
          tdXor.textContent = row.xorHex;
        }
        tr.appendChild(tdXor);

        // XOR Biner
        const tdBin = document.createElement('td');
        tdBin.appendChild(createColoredBinarySpan(row.xorBin));
        tr.appendChild(tdBin);

        // Status Kebocoran
        const tdStatus = document.createElement('td');
        if (row.isZero) {
          tdStatus.textContent = `BOCOR: Karakter Kembar ('${row.m1Char}')`;
          tdStatus.style.color = 'var(--color-status-error)';
          tdStatus.style.fontWeight = '600';
        } else {
          tdStatus.textContent = 'Karakter Berbeda';
          tdStatus.style.color = 'var(--color-bone-gray)';
        }
        tr.appendChild(tdStatus);

        dom.attackByteTbody.appendChild(tr);
      });

      // Tampilkan warning panjang jika ada
      if (result.lengthWarning) {
        showAlert(dom.attackAlert, result.lengthWarning, true);
      }

      // Jalankan crib drag otomatis jika ada tebakan
      handleDragCrib();

    } catch (err) {
      showAlert(dom.attackAlert, MESSAGES.UNEXPECTED_ERROR);
    }
  }

  function handleDragCrib() {
    if (!state.attackData || !state.attackData.c1XorC2Bytes) return;
    const crib = dom.cribInput.value;
    if (!crib) return;

    const dragResult = attack.cribDrag(state.attackData.c1XorC2Bytes, crib);
    if (!dragResult.ok) {
      dom.cribResultsTbody.innerHTML = `<tr><td colspan="5" style="color:var(--color-status-error);">${dragResult.error}</td></tr>`;
      return;
    }

    dom.cribResultsTbody.innerHTML = '';
    dragResult.candidates.forEach(cand => {
      const tr = document.createElement('tr');
      if (cand.isPrintable) {
        tr.className = 'crib-result-row printable';
      }

      const tdPos = document.createElement('td');
      tdPos.textContent = `Posisi ${cand.position}`;
      tr.appendChild(tdPos);

      const tdCrib = document.createElement('td');
      tdCrib.textContent = `"${cand.crib}"`;
      tdCrib.style.color = 'var(--color-muted-cobalt)';
      tr.appendChild(tdCrib);

      const tdFrag = document.createElement('td');
      tdFrag.textContent = `"${cand.fragment}"`;
      tdFrag.style.color = cand.isPrintable ? 'var(--color-gold-leaf)' : 'var(--color-bone-gray)';
      tdFrag.style.fontWeight = cand.isPrintable ? '600' : 'normal';
      tr.appendChild(tdFrag);

      const tdHex = document.createElement('td');
      tdHex.textContent = cand.fragmentHex;
      tr.appendChild(tdHex);

      const tdRead = document.createElement('td');
      if (cand.isPrintable) {
        tdRead.textContent = '✓ ASCII Terbaca (Plausible)';
        tdRead.style.color = 'var(--color-status-pass)';
      } else {
        tdRead.textContent = 'Non-printable byte (Mustahil)';
        tdRead.style.color = 'var(--color-bone-gray)';
      }
      tr.appendChild(tdRead);

      dom.cribResultsTbody.appendChild(tr);
    });
  }

  function handleRevealFullM2() {
    if (!state.attackData || !state.attackData.c1XorC2Bytes) return;
    const m1 = dom.attackM1.value;
    const rec = attack.recoverMessage2(state.attackData.c1XorC2Bytes, m1);

    dom.fullM2Val.textContent = rec.recoveredText;
    dom.fullM2Card.classList.remove('hidden');
  }

  function handleToggleDifferentKeys() {
    hideAlert(dom.attackAlert);
    dom.fullM2Card.classList.add('hidden');

    try {
      const m1 = dom.attackM1.value;
      const m2 = dom.attackM2.value;
      const sim = attack.simulateDifferentKeys(m1, m2);

      dom.attackC1Hex.textContent = sim.c1Hex;
      dom.attackC2Hex.textContent = sim.c2Hex;
      dom.attackC1xC2Hex.textContent = sim.c1XorC2Hex;
      dom.attackM1xM2Hex.textContent = sim.m1XorM2Hex;

      dom.attackIdenticalIndicator.innerHTML = `
        <span>C1 ⊕ C2 ≠ M1 ⊕ M2</span>
        <span style="color: var(--color-status-error); font-weight: 600;">✗ TIDAK IDENTIK — SERANGAN GAGAL KARENA KUNCI BERBEDA (K1 ≠ K2)</span>
      `;

      showAlert(
        dom.attackAlert,
        'Simulasi Sukses: Dua kunci acak berbeda dibuat untuk M1 dan M2. Operasi C1 ⊕ C2 menghasilkan derau acak baru (K1 ⊕ K2) sehingga tidak lagi membocorkan selisih pesan!',
        true
      );

      // Kosongkan tabel byte
      dom.attackByteTbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--color-pale-stone);">Kunci tidak digunakan ulang. Serangan key reuse tidak berlaku.</td></tr>';
      dom.cribResultsTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--color-pale-stone);">Crib dragging gagal karena keystream independen.</td></tr>';

    } catch (err) {
      showAlert(dom.attackAlert, MESSAGES.UNEXPECTED_ERROR);
    }
  }

  // =========================================================================
  // 6. Modul Pemeriksa Syarat OTP (Live OTP Inspector)
  // =========================================================================

  function updateOtpChecker() {
    const plain = dom.encPlain ? dom.encPlain.value : '';
    const key = dom.encKey ? dom.encKey.value : '';

    // 1. Syarat Panjang
    if (key.length >= plain.length && plain.length > 0) {
      dom.otpCheckLen.textContent = '✓ Memenuhi';
      dom.otpCheckLen.style.color = 'var(--color-status-pass)';
      dom.otpNoteLen.textContent = `Panjang kunci (${key.length}) ≥ panjang pesan (${plain.length}).`;
    } else {
      dom.otpCheckLen.textContent = '✗ Tidak Memenuhi';
      dom.otpCheckLen.style.color = 'var(--color-status-error)';
      dom.otpNoteLen.textContent = `Kunci (${key.length}) lebih pendek dari pesan (${plain.length}).`;
    }

    // 2. Syarat Acak
    if (state.isKeyRandomGenerated) {
      dom.otpCheckRnd.textContent = '✓ Dibuat Acak';
      dom.otpCheckRnd.style.color = 'var(--color-status-pass)';
      dom.otpNoteRnd.textContent = 'Kunci dibuat via CSPRNG (crypto.getRandomValues) tanpa bias.';
    } else {
      dom.otpCheckRnd.textContent = '? Tidak Terverifikasi';
      dom.otpCheckRnd.style.color = 'var(--color-status-warn)';
      dom.otpNoteRnd.textContent = 'Kunci diketik manual atau diubah. Gunakan tombol "Acak kunci".';
    }

    // 3. Syarat Belum Pernah Dipakai (Reuse)
    if (state.usedKeysMap.has(key)) {
      const pastMessages = state.usedKeysMap.get(key);
      if (pastMessages.size > 1 || (pastMessages.size === 1 && !pastMessages.has(plain))) {
        dom.otpCheckReuse.textContent = '✗ REUSE TERDETEKSI!';
        dom.otpCheckReuse.style.color = 'var(--color-status-error)';
        dom.otpNoteReuse.textContent = 'Kunci ini sudah pernah digunakan untuk pesan berbeda dalam sesi ini! Rawan Two-Time Pad.';
      } else {
        dom.otpCheckReuse.textContent = '✓ Belum Reuse';
        dom.otpCheckReuse.style.color = 'var(--color-status-pass)';
        dom.otpNoteReuse.textContent = 'Kunci baru dipakai 1 kali untuk pesan saat ini.';
      }
    } else {
      dom.otpCheckReuse.textContent = '✓ Belum Dipakai';
      dom.otpCheckReuse.style.color = 'var(--color-status-pass)';
      dom.otpNoteReuse.textContent = 'Kunci ini belum pernah dienkripsi dalam sesi ini.';
    }
  }

  // =========================================================================
  // 7. Event Listeners Wiring
  // =========================================================================

  function initEventListeners() {
    // Enkripsi
    dom.encPlain.addEventListener('input', () => {
      updateEncCounters();
      hideAlert(dom.encAlert);
    });

    dom.encKey.addEventListener('input', () => {
      state.isKeyRandomGenerated = false; // Kunci diubah manual
      updateEncCounters();
      hideAlert(dom.encAlert);
    });

    dom.encModeStream.addEventListener('click', () => setEncMode('stream'));
    dom.encModeOtp.addEventListener('click', () => setEncMode('otp'));
    dom.btnRandomKey.addEventListener('click', handleRandomKey);
    dom.btnEncrypt.addEventListener('click', handleEncrypt);
    dom.btnCopyCipher.addEventListener('click', () => copyToClipboard(dom.encOutputVal.textContent, dom.btnCopyCipher));
    dom.btnSendToDecrypt.addEventListener('click', handleSendToDecrypt);

    // Dekripsi
    dom.decCipher.addEventListener('input', () => hideAlert(dom.decAlert));
    dom.decKey.addEventListener('input', () => hideAlert(dom.decAlert));
    dom.decModeStream.addEventListener('click', () => setDecMode('stream'));
    dom.decModeOtp.addEventListener('click', () => setDecMode('otp'));
    dom.btnDecrypt.addEventListener('click', handleDecrypt);
    dom.btnCopyPlain.addEventListener('click', () => copyToClipboard(dom.decOutputVal.textContent, dom.btnCopyPlain));

    // Visualisasi
    if (dom.btnVisNext) dom.btnVisNext.addEventListener('click', nextStepManual);
    if (dom.btnVisAll) dom.btnVisAll.addEventListener('click', showAllSteps);

    // Tests
    dom.btnRunAllTests.addEventListener('click', runAndRenderTests);
    dom.btnRunCustomTest.addEventListener('click', handleRunCustomTest);

    // Serangan Key Reuse
    dom.btnAttackRandomKey.addEventListener('click', () => {
      const len = Math.max(dom.attackM1.value.length, dom.attackM2.value.length);
      dom.attackKey.value = cipher.generateRandomKey(len || 15);
      hideAlert(dom.attackAlert);
    });
    dom.btnRunAttack.addEventListener('click', runAttackAnalysis);
    dom.btnToggleDiffKey.addEventListener('click', handleToggleDifferentKeys);
    dom.btnDragCrib.addEventListener('click', handleDragCrib);
    dom.cribInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleDragCrib();
    });
    dom.btnRevealFullM2.addEventListener('click', handleRevealFullM2);

    // Smooth Anchor Scroll & Active Spy
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function (e) {
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;
        const targetEl = document.querySelector(targetId);
        if (targetEl) {
          e.preventDefault();
          targetEl.scrollIntoView({ behavior: 'smooth' });
        }
      });
    });
  }

  // =========================================================================
  // Inisialisasi Awal Halaman
  // =========================================================================
  document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    updateEncCounters();

    // Jalankan Enkripsi awal agar contoh tampil siap pakai
    handleEncrypt();

    // Jalankan tes otomatis saat halaman dimuat
    runAndRenderTests();

    // Jalankan demo analisis serangan awal
    runAttackAnalysis();
  });

})();
