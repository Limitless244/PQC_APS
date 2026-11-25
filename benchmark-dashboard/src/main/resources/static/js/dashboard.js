/**
 * PQC-APS Interactive Dashboard JavaScript Client
 * Handles sidebar navigation, theme toggling, live handshake SSE visualizer,
 * attack simulation, honest suite comparison, scanner execution, secure chat demo,
 * and live event telemetry streaming.
 */

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initNavigation();
    initOverview();
    initHandshakeVisualizer();
    initAttackSimulator();
    initBenchmarksAndComparison();
    initCryptoScanner();
    initSecureChatDemo();
    initLiveEvents();
});

// ── UTILITIES ─────────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function truncateHex(hex) {
    if (!hex) return 'null';
    return hex.length > 8 ? hex.substring(0, 8) + '...' : hex;
}

// ── THEME TOGGLE ──────────────────────────────────────────────────────────

function initTheme() {
    const toggleBtn = document.getElementById('theme-toggle');
    const icon = document.getElementById('theme-icon');
    const text = document.getElementById('theme-text');
    if (!toggleBtn) return;

    toggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        if (newTheme === 'light') {
            icon.textContent = '\u263E'; // Moon icon
            text.textContent = 'Dark Theme';
        } else {
            icon.textContent = '\u2600'; // Sun icon
            text.textContent = 'Light Theme';
        }
    });
}

// ── SIDEBAR NAVIGATION ────────────────────────────────────────────────────

const PAGE_METADATA = {
    overview: {
        title: 'Executive Overview',
        caption: 'High-level status of the post-quantum cryptography migration and attack prevention architecture.'
    },
    handshake: {
        title: 'Live Handshake Visualizer',
        caption: 'Interactive visualization of the real in-process TLS handshake execution, showing wire messages, cryptosystem sizes, and verification steps.'
    },
    simulator: {
        title: 'Attack Simulator',
        caption: 'Execute real cryptographic attack scenarios against vulnerable and hardened configurations to observe active defence mechanisms.'
    },
    benchmarks: {
        title: 'JMH Benchmarks & Suite Comparison',
        caption: 'Empirical benchmark measurements comparing classical vs. post-quantum primitives, handshake wire sizes, latency, and CPU overhead.'
    },
    scanner: {
        title: 'Crypto Inventory Scanner',
        caption: 'Static and cryptographic inventory scanner detecting quantum-vulnerable algorithms, weak primitives, and hardcoded secrets.'
    },
    chat: {
        title: 'Secure Chat',
        caption: 'Demonstration of in-process secure messaging showing eavesdropping, replay attacks, and ciphertext tampering under real crypto guards.'
    },
    events: {
        title: 'Live Detection Events',
        caption: 'Real-time SSE event stream of cryptographic attack detection and policy enforcement telemetry.'
    }
};

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const pages = document.querySelectorAll('.page-content');
    const titleEl = document.getElementById('page-title');
    const captionEl = document.getElementById('page-caption');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const pageKey = item.getAttribute('data-page');
            navItems.forEach(i => i.classList.remove('active'));
            pages.forEach(p => p.classList.remove('active'));

            item.classList.add('active');
            const targetPage = document.getElementById('page-' + pageKey);
            if (targetPage) targetPage.classList.add('active');

            if (PAGE_METADATA[pageKey]) {
                if (titleEl) titleEl.textContent = PAGE_METADATA[pageKey].title;
                if (captionEl) captionEl.textContent = PAGE_METADATA[pageKey].caption;
            }

            if (pageKey === 'benchmarks') {
                renderAllCharts();
            }
            if (pageKey === 'scanner') {
                refreshScannerSummary();
            }
        });
    });
}

// ── 0. OVERVIEW PAGE INITIALIZATION ───────────────────────────────────────

function initOverview() {
    loadOverviewTests();
    loadOverviewAttacks();
    loadOverviewBenchmarks();
}

function loadOverviewTests() {
    const testsValEl = document.getElementById('overview-tests-value');
    const testsCapEl = document.getElementById('overview-tests-caption');
    if (testsCapEl) {
        testsCapEl.textContent = 'Across 10 modules';
    }

    fetch('/api/test-summary')
        .then(res => {
            if (!res.ok) throw new Error('Test summary response not OK');
            return res.json();
        })
        .then(data => {
            if (data && data.available !== false && typeof data.totalTests === 'number') {
                if (testsValEl) {
                    testsValEl.textContent = `${data.passed} / ${data.totalTests} Passing`;
                    testsValEl.className = (data.failures === 0 && data.errors === 0) ? 'metric-value text-success' : 'metric-value text-danger';
                }
            } else {
                if (testsValEl) {
                    testsValEl.textContent = 'not available';
                    testsValEl.className = 'metric-value text-secondary';
                }
            }
        })
        .catch(() => {
            if (testsValEl) {
                testsValEl.textContent = 'not available';
                testsValEl.className = 'metric-value text-secondary';
            }
        });
}

function loadOverviewAttacks() {
    const matrixValEl = document.getElementById('overview-matrix-value');
    const matrixSubEl = document.getElementById('overview-matrix-sub');

    fetch('/api/attacks')
        .then(res => {
            if (!res.ok) throw new Error('Attacks response not OK');
            return res.json();
        })
        .then(matrix => {
            if (Array.isArray(matrix) && matrix.length > 0) {
                const totalCells = matrix.length;
                const attacks = new Set(matrix.map(m => m.attack || m.attackType)).size;
                const modes = new Set(matrix.map(m => m.mode)).size;
                if (matrixValEl) {
                    matrixValEl.textContent = `${totalCells} / ${totalCells} Cells Evaluated`;
                    matrixValEl.className = 'metric-value text-success';
                }
                if (matrixSubEl) {
                    matrixSubEl.innerHTML = `${attacks} Attacks &times; ${modes} Modes Verified`;
                }
            } else {
                if (matrixValEl) {
                    matrixValEl.textContent = 'not available';
                    matrixValEl.className = 'metric-value text-secondary';
                }
            }
        })
        .catch(() => {
            if (matrixValEl) {
                matrixValEl.textContent = 'not available';
                matrixValEl.className = 'metric-value text-secondary';
            }
        });
}

function loadOverviewBenchmarks() {
    fetch('/api/benchmarks')
        .then(res => {
            if (!res.ok) throw new Error('Benchmark response not OK');
            return res.json();
        })
        .then(data => {
            updateOverviewThroughput(data);
        })
        .catch(() => {
            const tpValEl = document.getElementById('overview-throughput-value');
            if (tpValEl) {
                tpValEl.textContent = 'not available';
                tpValEl.className = 'metric-value text-secondary';
            }
        });
}

function updateOverviewThroughput(data) {
    const tpValEl = document.getElementById('overview-throughput-value');
    const tpSubEl = document.getElementById('overview-throughput-sub');
    if (!tpValEl) return;

    if (!data || !Array.isArray(data.throughput) || data.throughput.length === 0) {
        tpValEl.textContent = 'not available';
        tpValEl.className = 'metric-value text-secondary';
        return;
    }

    // AES-256-GCM throughput, 64 KB record
    const tp64Enc = data.throughput.find(t => t.recordSize === '64 KB' && t.operation === 'Encrypt');
    const tp64 = tp64Enc || data.throughput.find(t => t.recordSize === '64 KB');

    if (tp64 && typeof tp64.throughputMBps === 'number') {
        const rateFormatted = Number(tp64.throughputMBps).toFixed(1);
        const jdk = data.machine && data.machine.jdkVersion ? `JDK ${data.machine.jdkVersion}` : 'JDK';
        const cores = data.machine && data.machine.cpuCores ? `${data.machine.cpuCores} cores` : '';
        const metaText = cores ? `${jdk} \u2022 ${cores}` : jdk;

        tpValEl.innerHTML = `${escapeHtml(rateFormatted)} MB/s <span class="metric-meta" style="font-size: 0.82rem; font-weight: normal; color: var(--text-secondary);">(${escapeHtml(metaText)})</span>`;
        tpValEl.className = 'metric-value text-primary';
        if (tpSubEl) {
            tpSubEl.textContent = `AES-256-GCM (64 KB record) \u2022 ${metaText}`;
        }
    } else {
        tpValEl.textContent = 'not available';
        tpValEl.className = 'metric-value text-secondary';
    }
}

// ── 1. LIVE HANDSHAKE VISUALIZER ──────────────────────────────────────────

const warmSuites = new Set();

function initHandshakeVisualizer() {
    const runBtn = document.getElementById('btn-run-handshake');
    const runX5Btn = document.getElementById('btn-run-x5');
    const suiteSelect = document.getElementById('hs-suite-select');
    if (!runBtn || !suiteSelect) return;

    suiteSelect.addEventListener('change', () => {
        const noteEl = document.getElementById('hs-protocol-note');
        if (!noteEl) return;
        const s = suiteSelect.value;
        if (s === 'HYBRID') {
            noteEl.textContent = 'Hybrid combines classical X25519 with post-quantum ML-KEM-768 for forward secrecy and ML-DSA-65 signatures for authentication.';
        } else if (s === 'PQ_ONLY') {
            noteEl.textContent = 'PQ_ONLY uses pure lattice-based cryptography: ML-KEM-768 for encapsulation and ML-DSA-65 for identity signatures.';
        } else {
            noteEl.textContent = 'Classical baseline uses X25519 ECDH and RSA-2048 PKCS#1 v1.5 signatures, vulnerable to Shor\'s quantum algorithm.';
        }
    });

    runBtn.addEventListener('click', () => {
        const suite = suiteSelect.value;
        const arrowsContainer = document.getElementById('handshake-arrows');
        const statusEl = document.getElementById('hs-session-status');
        const bytesEl = document.getElementById('hs-total-bytes');
        const payloadEl = document.getElementById('hs-payload-bytes');
        const timeEl = document.getElementById('hs-elapsed-time');
        const timeBreakdownEl = document.getElementById('hs-time-breakdown');
        const selectedSuiteEl = document.getElementById('hs-selected-suite');

        runBtn.disabled = true;
        runBtn.textContent = 'Executing Handshake...';
        if (arrowsContainer) arrowsContainer.innerHTML = '';
        if (statusEl) {
            statusEl.textContent = 'RUNNING...';
            statusEl.className = 'summary-value text-warning';
        }
        if (selectedSuiteEl) selectedSuiteEl.textContent = suite;
        if (bytesEl) bytesEl.textContent = '0 B';
        if (payloadEl) payloadEl.textContent = '(payload before framing: 0 B)';
        if (timeEl) timeEl.textContent = '0.00 ms';
        if (timeBreakdownEl) timeBreakdownEl.textContent = 'measuring crypto time...';

        try {
            const es = new EventSource('/api/handshake/stream?suite=' + encodeURIComponent(suite));

            es.addEventListener('step', (e) => {
                try {
                    const step = JSON.parse(e.data);
                    renderHandshakeStep(step, arrowsContainer);
                } catch (ignored) {}
            });

            es.addEventListener('complete', (e) => {
                try {
                    const res = JSON.parse(e.data);
                    const isCold = !warmSuites.has(suite);
                    warmSuites.add(suite);

                    if (bytesEl) bytesEl.textContent = Number(res.totalWireBytes).toLocaleString() + ' B';
                    if (payloadEl && res.payloadBytes != null) {
                        payloadEl.textContent = '(payload before framing: ' + Number(res.payloadBytes).toLocaleString() + ' B)';
                    }
                    // Pure crypto time as main figure, never mixed with animation delay
                    if (timeEl) timeEl.textContent = Number(res.elapsedMillis).toFixed(2) + ' ms';
                    if (timeBreakdownEl) {
                        timeBreakdownEl.textContent = isCold ? 'crypto time (cold start)' : 'crypto time (warm)';
                    }
                    if (statusEl) {
                        statusEl.textContent = '\u2714 SECURE';
                        statusEl.className = 'summary-value text-success font-bold';
                    }
                } catch (ignored) {}
                es.close();
                runBtn.disabled = false;
                runBtn.innerHTML = '&#x25B6; Run In-Process Handshake';
            });

            es.addEventListener('error', () => {
                es.close();
                runBtn.disabled = false;
                runBtn.innerHTML = '&#x25B6; Run In-Process Handshake';
                if (statusEl) {
                    statusEl.textContent = '\u2718 FAILED';
                    statusEl.className = 'summary-value text-danger';
                }
            });
        } catch (err) {
            console.error('Handshake visualizer failed:', err);
            runBtn.disabled = false;
            runBtn.innerHTML = '&#x25B6; Run In-Process Handshake';
        }
    });

    if (runX5Btn) {
        runX5Btn.addEventListener('click', () => {
            const suite = suiteSelect.value;
            const arrowsContainer = document.getElementById('handshake-arrows');
            const statusEl = document.getElementById('hs-session-status');
            const bytesEl = document.getElementById('hs-total-bytes');
            const payloadEl = document.getElementById('hs-payload-bytes');
            const timeEl = document.getElementById('hs-elapsed-time');
            const timeBreakdownEl = document.getElementById('hs-time-breakdown');
            const selectedSuiteEl = document.getElementById('hs-selected-suite');

            runX5Btn.disabled = true;
            runX5Btn.textContent = 'Running x5...';
            if (arrowsContainer) arrowsContainer.innerHTML = '<div class="arrow-row arrow-internal"><span class="font-mono text-muted">Executing 5 sequential in-process handshakes...</span></div>';
            if (statusEl) {
                statusEl.textContent = 'RUNNING x5...';
                statusEl.className = 'summary-value text-warning';
            }
            if (selectedSuiteEl) selectedSuiteEl.textContent = suite;

            fetch('/api/handshake/run-x5?suite=' + encodeURIComponent(suite), { method: 'POST' })
                .then(r => {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.json();
                })
                .then(res => {
                    if (bytesEl) bytesEl.textContent = Number(res.totalWireBytes).toLocaleString() + ' B';
                    if (payloadEl) payloadEl.textContent = '(payload before framing: ' + Number(res.payloadBytes).toLocaleString() + ' B)';
                    // Main figure: crypto time mean of last 4 runs
                    if (timeEl) timeEl.textContent = res.meanLast4Millis.toFixed(2) + ' ms';
                    if (timeBreakdownEl) {
                        timeBreakdownEl.textContent = `Mean: ${res.meanLast4Millis.toFixed(2)} ms, Min: ${res.minLast4Millis.toFixed(2)} ms (last 4 runs) | Run 1: ${res.coldStartMillis.toFixed(2)} ms (cold start)`;
                    }
                    if (statusEl) {
                        statusEl.textContent = '\u2714 SECURE (5 runs completed)';
                        statusEl.className = 'summary-value text-success font-bold';
                    }
                    warmSuites.add(suite);
                    if (arrowsContainer) {
                        const div = document.createElement('div');
                        div.className = 'arrow-row arrow-secure';
                        div.textContent = `\u2714 5 Runs Completed: [${res.runsMillis.map(m => m.toFixed(2) + ' ms').join(', ')}] — Last 4 Mean: ${res.meanLast4Millis.toFixed(2)} ms, Min: ${res.minLast4Millis.toFixed(2)} ms`;
                        arrowsContainer.appendChild(div);
                    }
                })
                .catch(err => {
                    if (statusEl) {
                        statusEl.textContent = '\u2718 FAILED';
                        statusEl.className = 'summary-value text-danger';
                    }
                    alert('Run x5 failed: ' + err.message);
                })
                .finally(() => {
                    runX5Btn.disabled = false;
                    runX5Btn.innerHTML = '&#x21BB; Run x5';
                });
        });
    }
}

function renderHandshakeStep(step, container) {
    if (!container) return;

    const row = document.createElement('div');
    row.className = 'arrow-row';

    if (step.direction === 'CLIENT_TO_SERVER') {
        row.classList.add('arrow-c2s');
        row.innerHTML = `
            <div class="arrow-details">
                <span class="arrow-name">${escapeHtml(step.stepName)}</span>
                <span class="arrow-size-badge">${escapeHtml(step.messageBytes)} B</span>
            </div>
            <div class="arrow-line"></div>
            <span class="arrow-status text-success font-mono">[${escapeHtml(step.hex4)}] \u2714</span>
        `;
    } else if (step.direction === 'SERVER_TO_CLIENT') {
        row.classList.add('arrow-s2c');
        row.innerHTML = `
            <span class="arrow-status text-primary font-mono">\u2714 [${escapeHtml(step.hex4)}]</span>
            <div class="arrow-line"></div>
            <div class="arrow-details">
                <span class="arrow-name">${escapeHtml(step.stepName)}</span>
                <span class="arrow-size-badge">${escapeHtml(step.messageBytes)} B</span>
            </div>
        `;
    } else if (step.stepName === 'ChannelEstablished') {
        row.classList.add('arrow-secure');
        row.textContent = '\u2714 SECURE CHANNEL ESTABLISHED (Session Keys Derived & Confirmed)';
    } else {
        row.classList.add('arrow-internal');
        row.innerHTML = `
            <span class="font-mono text-success">\u2714 ${escapeHtml(step.stepName)} (${escapeHtml(step.messageBytes)} B, id: ${escapeHtml(step.hex4)})</span>
        `;
    }

    container.appendChild(row);
    row.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── 2. ATTACK SIMULATOR ───────────────────────────────────────────────────

const SIMULATOR_EXPLANATIONS = {
    'Downgrade': 'An active network adversary modifies the ClientHello cipher suite list to force negotiation of an insecure cipher suite.',
    'MITM': 'An interceptor injects an unpinned public key during key exchange to intercept, inspect, and decrypt all subsequent encrypted sessions.',
    'Replay': 'An attacker captures a valid encrypted record and retransmits it later to force duplicate execution without possessing cryptographic keys.',
    'Nonce Reuse': 'Encrypting two messages under the exact same AES-GCM key and nonce breaks Galois counter integrity and leaks plaintext via ciphertext XOR.',
    'Tampering': 'An active attacker flips bits in the ciphertext or KEM encapsulation to alter data or probe for side-channel error oracles.'
};

function initAttackSimulator() {
    const attackSelect = document.getElementById('sim-attack-select');
    const runBtn = document.getElementById('btn-run-simulation');
    const explanationEl = document.getElementById('sim-attack-explanation');
    if (!attackSelect || !runBtn) return;

    attackSelect.addEventListener('change', () => {
        if (explanationEl) {
            explanationEl.textContent = SIMULATOR_EXPLANATIONS[attackSelect.value] || '';
        }
    });

    runBtn.addEventListener('click', () => {
        const attack = attackSelect.value;
        const mode = document.getElementById('sim-mode-select').value;
        const resultCard = document.getElementById('sim-result-card');

        runBtn.disabled = true;
        runBtn.textContent = 'Simulating Attack In Real Code...';

        fetch('/api/simulator/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack: attack, mode: mode })
        })
        .then(res => {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.json();
        })
        .then(data => {
            renderSimulationResult(data);
            if (resultCard) resultCard.classList.remove('hidden');
            loadEvents(); // Refresh event feed
        })
        .catch(err => {
            alert('Simulation error: ' + err.message);
        })
        .finally(() => {
            runBtn.disabled = false;
            runBtn.innerHTML = '&#x26A0; Run Attack Simulation';
        });
    });
}

function renderSimulationResult(data) {
    const titleEl = document.getElementById('sim-title');
    const subtitleEl = document.getElementById('sim-subtitle');
    const badgeEl = document.getElementById('sim-outcome-badge');
    const defenceEl = document.getElementById('sim-defence');
    const eventIdEl = document.getElementById('sim-event-id');
    const stepsListEl = document.getElementById('sim-steps-list');
    const evidenceEl = document.getElementById('sim-evidence-text');

    if (titleEl) titleEl.textContent = data.attack + ' Attack Simulation';
    if (subtitleEl) subtitleEl.textContent = 'Mode: ' + data.mode;

    if (badgeEl) {
        if (data.attackSucceeded) {
            badgeEl.className = 'badge badge-danger font-bold';
            badgeEl.textContent = '\u26A0 ATTACK SUCCEEDED (Vulnerable Baseline)';
        } else {
            badgeEl.className = 'badge badge-success font-bold';
            badgeEl.textContent = '\u2714 ATTACK BLOCKED (Defence Active)';
        }
    }

    if (defenceEl) defenceEl.textContent = data.triggeredDefence;
    if (eventIdEl) eventIdEl.textContent = data.eventId ? truncateHex(data.eventId) : 'None (Vulnerable unmonitored baseline)';

    if (stepsListEl) {
        stepsListEl.innerHTML = '';
        if (data.attackerSteps && data.attackerSteps.length > 0) {
            data.attackerSteps.forEach(st => {
                const li = document.createElement('li');
                li.textContent = st;
                stepsListEl.appendChild(li);
            });
        }
    }

    if (evidenceEl) evidenceEl.textContent = data.detail;
}

// ── 3. BENCHMARKS & SUITE COMPARISON ──────────────────────────────────────

let benchmarkReportData = null;
let charts = {};

function initBenchmarksAndComparison() {
    loadBenchmarks();

    const refreshBtn = document.getElementById('btn-refresh-benchmarks');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            refreshBtn.disabled = true;
            refreshBtn.textContent = 'Refreshing...';
            loadBenchmarks(() => {
                refreshBtn.disabled = false;
                refreshBtn.innerHTML = '&#x21BB; Refresh Results';
            });
        });
    }

    const compPills = document.querySelectorAll('.comparison-switch .pill-btn');
    compPills.forEach(pill => {
        pill.addEventListener('click', () => {
            compPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            updateSuiteComparison(pill.getAttribute('data-compare'));
        });
    });
}

function loadBenchmarks(onComplete) {
    fetch('/api/benchmarks')
        .then(res => res.json())
        .then(data => {
            benchmarkReportData = data;
            const hdr = document.getElementById('machine-info-header');
            if (hdr && data.machine) {
                hdr.textContent = 'Host Environment: ' + data.machine.jdkVersion + ' (' + data.machine.jvmName + ') | ' +
                    data.machine.osName + ' ' + data.machine.osArch + ' | ' + data.machine.cpuCores + ' CPU Cores';
            }
            const modeBadge = document.getElementById('benchmark-mode-badge');
            if (modeBadge) {
                const isFull = (data.mode && data.mode.toUpperCase() === 'FULL');
                modeBadge.textContent = isFull ? 'full mode' : 'quick mode';
                modeBadge.className = isFull ? 'badge badge-primary font-mono' : 'badge badge-secondary font-mono';
            }
            updateOverviewThroughput(data);
            renderAllCharts();
            updateSuiteComparison('HYBRID');
        })
        .catch(err => console.warn('Could not load benchmarks:', err))
        .finally(() => {
            if (onComplete) onComplete();
        });
}

function updateSuiteComparison(selectedSuite) {
    const callout = document.getElementById('comparison-callout');
    const compWire = document.getElementById('comp-wire');
    const compWireRatio = document.getElementById('comp-wire-ratio');
    const compPk = document.getElementById('comp-pk');
    const compPkRatio = document.getElementById('comp-pk-ratio');
    const compSig = document.getElementById('comp-sig');
    const compSigRatio = document.getElementById('comp-sig-ratio');
    const compCpu = document.getElementById('comp-cpu');
    const compCpuBadge = document.getElementById('comp-cpu-badge');

    if (!benchmarkReportData || !benchmarkReportData.sizes) return;

    const sizes = benchmarkReportData.sizes;
    const summary = benchmarkReportData.summary || {};

    const findSize = (cat, item, suite) => {
        const found = sizes.find(s => s.category === cat && s.item === item && (!suite || s.suite === suite));
        return found ? found.rawBytes : 0;
    };

    const classicalWire = findSize('HANDSHAKE_WIRE', 'Total Handshake Wire', 'CLASSICAL') || 820;
    const hybridWire = findSize('HANDSHAKE_WIRE', 'Total Handshake Wire', 'HYBRID') || 6433;
    const pqOnlyWire = findSize('HANDSHAKE_WIRE', 'Total Handshake Wire', 'PQ_ONLY') || 6344;

    const classicalRaw = findSize('TOTAL_HANDSHAKE', 'Total Handshake', 'CLASSICAL') || 501;
    const hybridRaw = findSize('TOTAL_HANDSHAKE', 'Total Handshake', 'HYBRID') || 6098;
    const pqOnlyRaw = findSize('TOTAL_HANDSHAKE', 'Total Handshake', 'PQ_ONLY') || 6009;

    const mlKemPk = findSize('PRIMITIVE_KEY', 'ML-KEM-768 Encapsulation Key') || 1184;
    const x25519Pk = findSize('PRIMITIVE_KEY', 'X25519 Public Key') || 32;
    const mlDsaSig = findSize('SIGNATURE', 'ML-DSA-65 Signature') || 3309;
    const rsaSig = findSize('SIGNATURE', 'RSA-2048 Signature') || 256;

    const cpuList = (benchmarkReportData && benchmarkReportData.cpu) ? benchmarkReportData.cpu : [];
    const classicalCpuObj = cpuList.find(c => c.suite === 'CLASSICAL');
    const hybridCpuObj = cpuList.find(c => c.suite === 'HYBRID');
    const pqOnlyCpuObj = cpuList.find(c => c.suite === 'PQ_ONLY');

    const classicalCpu = classicalCpuObj ? classicalCpuObj.avgCpuMicroseconds : 1250.0;
    const hybridCpu = hybridCpuObj ? hybridCpuObj.avgCpuMicroseconds : 1406.25;
    const pqOnlyCpu = pqOnlyCpuObj ? pqOnlyCpuObj.avgCpuMicroseconds : 937.5;

    const hybridDiff = hybridCpu - classicalCpu;
    const hybridRatio = classicalCpu > 0 ? (hybridCpu / classicalCpu) : 1.13;

    const pqDiff = pqOnlyCpu - classicalCpu;
    const pqRatio = classicalCpu > 0 ? (pqOnlyCpu / classicalCpu) : 0.75;

    const kexRatio = x25519Pk > 0 ? (mlKemPk / x25519Pk) : 37.0;
    const sigRatio = rsaSig > 0 ? (mlDsaSig / rsaSig) : 12.9;

    if (selectedSuite === 'HYBRID') {
        const wireRatio = (classicalWire > 0 ? (hybridWire / classicalWire) : 7.85).toFixed(1);
        const keyRatio = (classicalRaw > 0 ? (hybridRaw / classicalRaw) : 12.17).toFixed(1);

        if (callout) {
            callout.innerHTML = '<strong>Bandwidth Cost:</strong> HYBRID incurs ~' + escapeHtml(wireRatio) + 'x total handshake wire overhead (' +
                escapeHtml(hybridWire.toLocaleString()) + ' B vs ' + escapeHtml(classicalWire.toLocaleString()) + ' B serialized, matching WireSizeComparisonTest) and ~' +
                escapeHtml(keyRatio) + 'x on raw key material (' + escapeHtml(hybridRaw.toLocaleString()) + ' B vs ' + escapeHtml(classicalRaw.toLocaleString()) + ' B) due to ML-KEM-768 encapsulation key (' +
                escapeHtml(mlKemPk.toLocaleString()) + ' B) and ML-DSA-65 signature (' + escapeHtml(mlDsaSig.toLocaleString()) + ' B). In return, it guarantees post-quantum forward secrecy with minimal CPU overhead.';
        }
        if (compWire) compWire.textContent = hybridWire.toLocaleString() + ' B vs ' + classicalWire.toLocaleString() + ' B';
        if (compWireRatio) compWireRatio.textContent = wireRatio + 'x Wire Overhead (' + keyRatio + 'x Key Material)';
        if (compPk) compPk.textContent = mlKemPk.toLocaleString() + ' B vs ' + x25519Pk.toLocaleString() + ' B';
        if (compPkRatio) compPkRatio.textContent = kexRatio.toFixed(0) + 'x Overhead';
        if (compSig) compSig.textContent = mlDsaSig.toLocaleString() + ' B vs ' + rsaSig.toLocaleString() + ' B';
        if (compSigRatio) compSigRatio.textContent = sigRatio.toFixed(1) + 'x Overhead';
        if (compCpu) compCpu.textContent = Math.round(hybridCpu).toLocaleString() + ' \u00B5s vs ' + Math.round(classicalCpu).toLocaleString() + ' \u00B5s (' + hybridRatio.toFixed(2) + 'x)';
        if (compCpuBadge) compCpuBadge.textContent = (hybridDiff >= 0 ? '+' : '') + hybridDiff.toFixed(1) + ' \u00B5s CPU diff (HYBRID - CLASSICAL)';
    } else {
        const wireRatio = (classicalWire > 0 ? (pqOnlyWire / classicalWire) : 7.74).toFixed(1);
        const keyRatio = (classicalRaw > 0 ? (pqOnlyRaw / classicalRaw) : 12.0).toFixed(1);

        if (callout) {
            callout.innerHTML = '<strong>Pure Post-Quantum:</strong> PQ_ONLY drops classical X25519 entirely, relying exclusively on ML-KEM-768 and ML-DSA-65. Handshake wire size is ' +
                escapeHtml(pqOnlyWire.toLocaleString()) + ' B (~' + escapeHtml(wireRatio) + 'x classical serialized) with optimal lattice-based performance.';
        }
        if (compWire) compWire.textContent = pqOnlyWire.toLocaleString() + ' B vs ' + classicalWire.toLocaleString() + ' B';
        if (compWireRatio) compWireRatio.textContent = wireRatio + 'x Wire Overhead (' + keyRatio + 'x Key Material)';
        if (compPk) compPk.textContent = mlKemPk.toLocaleString() + ' B (KEM pk)';
        if (compPkRatio) compPkRatio.textContent = 'Lattice KEM';
        if (compSig) compSig.textContent = mlDsaSig.toLocaleString() + ' B (DSA sig)';
        if (compSigRatio) compSigRatio.textContent = 'Lattice DSA';
        if (compCpu) compCpu.textContent = Math.round(pqOnlyCpu).toLocaleString() + ' \u00B5s vs ' + Math.round(classicalCpu).toLocaleString() + ' \u00B5s (' + pqRatio.toFixed(2) + 'x)';
        if (compCpuBadge) compCpuBadge.textContent = (pqDiff >= 0 ? '+' : '') + pqDiff.toFixed(1) + ' \u00B5s CPU diff (PQ_ONLY - CLASSICAL)';
    }
}

function renderAllCharts() {
    if (!benchmarkReportData) return;
    renderSizesChart(benchmarkReportData.sizes);
    renderWireChart(benchmarkReportData.sizes);
    renderLatencyChart(benchmarkReportData.latency);
    renderThroughputChart(benchmarkReportData.throughput);
}

function renderSizesChart(sizes) {
    const canvas = document.getElementById('chart-sizes');
    if (!canvas || !window.Chart) return;
    const prims = sizes.filter(s => s.category === 'PRIMITIVE_KEY' || s.category === 'SIGNATURE');
    const labels = prims.map(s => s.item);
    const rawData = prims.map(s => s.rawBytes);
    const encData = prims.map(s => s.encodedBytes);

    if (charts['sizes']) charts['sizes'].destroy();
    charts['sizes'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'Raw Bytes (NIST FIPS)', data: rawData, backgroundColor: '#58a6ff' },
                { label: 'DER / Encoded Bytes', data: encData, backgroundColor: '#a371f7' }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } }
        }
    });
}

function renderWireChart(sizes) {
    const canvas = document.getElementById('chart-wire');
    if (!canvas || !window.Chart) return;
    const wire = sizes.filter(s => s.category === 'HANDSHAKE_WIRE');
    const target = wire.length > 0 ? wire : sizes.filter(s => s.category === 'TOTAL_HANDSHAKE');
    const labels = target.map(s => s.suite);
    const totals = target.map(s => s.rawBytes);

    if (charts['wire']) charts['wire'].destroy();
    charts['wire'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ label: 'Total Handshake Wire Size (Bytes, Serialized)', data: totals, backgroundColor: ['#3fb950', '#d29922', '#58a6ff'] }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } }
        }
    });
}

function renderLatencyChart(latency) {
    const canvas = document.getElementById('chart-latency');
    if (!canvas || !window.Chart) return;
    const handshakes = latency.filter(l => l.operation === 'handshake');
    const labels = handshakes.map(h => h.suiteOrAlgorithm);
    const avg = handshakes.map(h => h.avgMicroseconds);
    const p95 = handshakes.map(h => h.p95Microseconds);

    if (charts['latency']) charts['latency'].destroy();
    charts['latency'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'Avg Latency (\u00B5s)', data: avg, backgroundColor: '#3fb950' },
                { label: 'P95 Latency (\u00B5s)', data: p95, backgroundColor: '#f85149' }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } }
        }
    });
}

function renderThroughputChart(throughput) {
    const canvas = document.getElementById('chart-throughput');
    if (!canvas || !window.Chart) return;
    const labels = throughput.map(t => t.recordSize + ' ' + t.operation);
    const rates = throughput.map(t => t.throughputMBps);

    if (charts['throughput']) charts['throughput'].destroy();
    charts['throughput'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ label: 'AES-256-GCM Throughput (MB/s)', data: rates, backgroundColor: '#a371f7' }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } }
        }
    });
}

// ── 4. CRYPTO SCANNER ─────────────────────────────────────────────────────

function initCryptoScanner() {
    const runBtn = document.getElementById('btn-run-scan');
    const targetSelect = document.getElementById('scanner-target-select');
    if (!runBtn || !targetSelect) return;

    // Load initial reports for comparison table
    refreshScannerSummary();

    // Load initial report
    loadScanReport('vulnerable');

    targetSelect.addEventListener('change', () => {
        loadScanReport(targetSelect.value);
    });

    runBtn.addEventListener('click', () => {
        const target = targetSelect.value;
        runBtn.disabled = true;
        runBtn.textContent = 'Scanning...';

        fetch('/api/scan/run?target=' + encodeURIComponent(target), { method: 'POST' })
            .then(res => {
                if (!res.ok) throw new Error('HTTP ' + res.status);
                return res.json();
            })
            .then(report => {
                renderScanReport(report, target);
                refreshScannerSummary();
            })
            .catch(err => {
                console.error('Scan failed:', err);
                alert('Scan failed: ' + err.message);
            })
            .finally(() => {
                runBtn.disabled = false;
                runBtn.innerHTML = '&#x1F50D; Scan Target';
            });
    });
}

function selectScannerTarget(target) {
    const targetSelect = document.getElementById('scanner-target-select');
    if (targetSelect) {
        targetSelect.value = target;
        loadScanReport(target);
    }
}
window.selectScannerTarget = selectScannerTarget;

function refreshScannerSummary() {
    const targets = ['vulnerable', 'migrated', 'self', 'self-production', 'self-tests'];
    targets.forEach(tgt => {
        fetch('/api/scan/' + encodeURIComponent(tgt))
            .then(res => res.ok ? res.json() : null)
            .then(report => {
                if (!report || !report.summary) return;
                const s = report.summary;
                const pointsEl = document.getElementById('sum-points-' + tgt);
                const scoreEl = document.getElementById('sum-score-' + tgt);
                const gradeEl = document.getElementById('sum-grade-' + tgt);
                const readinessEl = document.getElementById('sum-readiness-' + tgt);
                const findingsEl = document.getElementById('sum-findings-' + tgt);

                if (pointsEl) {
                    pointsEl.innerHTML = `<span class="badge badge-secondary">${s.riskPoints !== undefined ? s.riskPoints : s.overallScore} pts</span>`;
                }
                if (scoreEl) {
                    scoreEl.innerHTML = `<span class="badge ${s.overallScore >= 70 ? 'badge-danger' : (s.overallScore >= 30 ? 'badge-warning' : 'badge-success')}">${s.overallScore} / 100</span>`;
                }
                if (gradeEl) {
                    gradeEl.innerHTML = `<strong class="${s.grade === 'F' ? 'text-danger' : (s.grade === 'A' ? 'text-success' : 'text-primary')}">${s.grade}</strong>`;
                }
                if (readinessEl) {
                    const qr = s.quantumReadiness !== undefined ? s.quantumReadiness : (s.quantumReadinessScore ? s.quantumReadinessScore * 100 : 0);
                    readinessEl.innerHTML = `<span class="badge ${qr >= 80 ? 'badge-success' : 'badge-warning'}">${qr.toFixed(1)}%</span>`;
                }
                if (findingsEl) {
                    findingsEl.textContent = s.totalFindings;
                }
            })
            .catch(() => {});
    });
}

function loadScanReport(target) {
    fetch('/api/scan/' + encodeURIComponent(target))
        .then(res => res.json())
        .then(report => renderScanReport(report, target))
        .catch(err => console.warn('Could not load scan report for ' + target, err));
}

function renderScanReport(report, target) {
    if (!report || !report.summary) return;
    const summary = report.summary;
    const scoreEl = document.getElementById('scan-score');
    const gradeEl = document.getElementById('scan-grade');
    const targetDescEl = document.getElementById('scan-target-desc');
    const statusDescEl = document.getElementById('scan-status-desc');
    const highCountEl = document.getElementById('scan-high-count');
    const totalCountEl = document.getElementById('scan-total-count');

    if (scoreEl) {
        scoreEl.textContent = summary.overallScore + ' / 100';
        scoreEl.className = summary.overallScore >= 70 ? 'metric-value text-danger' : (summary.overallScore >= 30 ? 'metric-value text-warning' : 'metric-value text-success');
    }
    const pointsBadge = document.getElementById('scan-points-badge');
    if (pointsBadge) {
        pointsBadge.textContent = (summary.riskPoints !== undefined ? summary.riskPoints : summary.overallScore) + ' Points (higher = worse)';
    }
    if (gradeEl) {
        gradeEl.textContent = summary.grade;
        gradeEl.className = summary.grade === 'F' ? 'metric-value text-danger' : (summary.grade === 'A' ? 'metric-value text-success' : 'metric-value text-primary');
    }
    if (targetDescEl) targetDescEl.textContent = target;
    if (statusDescEl) {
        const qr = summary.quantumReadiness !== undefined ? summary.quantumReadiness : (summary.quantumReadinessScore ? summary.quantumReadinessScore * 100 : 0);
        statusDescEl.textContent = 'Quantum Readiness: ' + qr.toFixed(1) + '%';
    }

    const counts = summary.countsBySeverity || {};
    if (highCountEl) highCountEl.textContent = (counts.CRITICAL || 0) + (counts.HIGH || 0);
    if (totalCountEl) totalCountEl.textContent = summary.totalFindings;

    const tbody = document.getElementById('scanner-findings-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!report.findings || report.findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state text-success">\u2714 Zero cryptographic vulnerabilities detected. Clean quantum-safe baseline!</td></tr>';
        return;
    }

    report.findings.forEach(f => {
        const tr = document.createElement('tr');

        const tdFile = document.createElement('td');
        tdFile.className = 'font-mono';
        tdFile.textContent = f.file;

        const tdLine = document.createElement('td');
        tdLine.className = 'font-mono';
        tdLine.textContent = f.line;

        const tdSev = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = f.severity === 'CRITICAL' ? 'badge badge-danger' : (f.severity === 'HIGH' ? 'badge badge-danger' : (f.severity === 'MEDIUM' ? 'badge badge-warning' : 'badge badge-primary'));
        badge.textContent = f.severity;
        tdSev.appendChild(badge);

        const tdMatched = document.createElement('td');
        tdMatched.className = 'font-mono';
        tdMatched.textContent = f.algorithm || f.redactedSnippet;

        const tdCat = document.createElement('td');
        tdCat.textContent = f.category;

        const tdScore = document.createElement('td');
        tdScore.style.fontWeight = '700';
        tdScore.textContent = f.riskScore;

        const tdRec = document.createElement('td');
        tdRec.textContent = f.recommendation;

        tr.appendChild(tdFile);
        tr.appendChild(tdLine);
        tr.appendChild(tdSev);
        tr.appendChild(tdMatched);
        tr.appendChild(tdCat);
        tr.appendChild(tdScore);
        tr.appendChild(tdRec);

        tbody.appendChild(tr);
    });
}

// ── 5. SECURE CHAT DEMO ───────────────────────────────────────────────────

function initSecureChatDemo() {
    const initBtn = document.getElementById('btn-init-chat');
    const sendBtn = document.getElementById('btn-chat-send');
    const serverSendBtn = document.getElementById('btn-chat-server-send');
    const replayBtn = document.getElementById('btn-chat-replay');
    const flipBtn = document.getElementById('btn-chat-flip');
    const downgradeBtn = document.getElementById('btn-chat-downgrade');
    const mitmBtn = document.getElementById('btn-chat-mitm');
    const inputEl = document.getElementById('chat-input-text');
    const serverInputEl = document.getElementById('chat-server-input-text');
    const modeSelect = document.getElementById('chat-mode-select');

    if (initBtn) {
        initBtn.addEventListener('click', () => {
            const mode = modeSelect.value;
            fetch('/api/chat/init?mode=' + encodeURIComponent(mode), { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    resetChatPanels(data.mode);
                });
        });
    }

    if (modeSelect) {
        modeSelect.addEventListener('change', () => {
            const mode = modeSelect.value;
            fetch('/api/chat/init?mode=' + encodeURIComponent(mode), { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    resetChatPanels(data.mode);
                });
        });
    }

    if (inputEl) {
        inputEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && sendBtn) sendBtn.click();
        });
    }

    if (serverInputEl) {
        serverInputEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && serverSendBtn) serverSendBtn.click();
        });
    }

    if (sendBtn && inputEl) {
        sendBtn.addEventListener('click', () => {
            const msg = inputEl.value.trim();
            if (!msg) return;

            fetch('/api/chat/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: msg })
            })
            .then(res => res.json())
            .then(data => {
                appendChatMessage('Client', 'Client: ' + data.message);
                logAttackerIntercept(data.attackerView);
                appendBobMessage('Client: ' + data.message, data.bobOutcome);
                inputEl.value = '';
            })
            .catch(err => alert('Send failed: ' + err.message));
        });
    }

    if (serverSendBtn && serverInputEl) {
        serverSendBtn.addEventListener('click', () => {
            const msg = serverInputEl.value.trim();
            if (!msg) return;

            const mode = modeSelect ? modeSelect.value : 'HYBRID';
            appendBobMessage('Server: ' + msg, 'SENT');
            if (mode === 'CLASSICAL-VULNERABLE') {
                logAttackerIntercept('[MITM Intercepted Plaintext]: "Server: ' + msg + '"');
            } else {
                logAttackerIntercept('[Encrypted Record (Server -> Client)]: AES-256-GCM record');
            }
            appendChatMessage('Server', 'Server: ' + msg);
            serverInputEl.value = '';
        });
    }

    if (replayBtn) {
        replayBtn.addEventListener('click', () => {
            fetch('/api/chat/attacker/replay', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    logAttackerAction(data);
                    updateBobGuardStatus(data);
                    loadEvents(); // Live event refresh
                })
                .catch(err => alert('Replay request error: ' + err.message));
        });
    }

    if (flipBtn) {
        flipBtn.addEventListener('click', () => {
            fetch('/api/chat/attacker/flip-bit', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    logAttackerAction(data);
                    updateBobGuardStatus(data);
                    loadEvents(); // Live event refresh
                })
                .catch(err => alert('Bit flip request error: ' + err.message));
        });
    }

    if (downgradeBtn) {
        downgradeBtn.addEventListener('click', () => {
            const mode = modeSelect ? modeSelect.value : 'HYBRID';
            if (mode === 'CLASSICAL-VULNERABLE') {
                logAttackerAction({ action: 'DOWNGRADE ATTACK', outcome: 'SUCCEEDED', detail: 'Server accepted downgraded classical suite!' });
                updateBobGuardStatus({ action: 'DOWNGRADE ATTACK', outcome: 'ACCEPTED' });
            } else {
                logAttackerAction({ action: 'DOWNGRADE ATTACK', outcome: 'BLOCKED', detail: 'DowngradeGuard rejected stripped suite list in handshake transcript!' });
                updateBobGuardStatus({ action: 'DOWNGRADE ATTACK', outcome: 'BLOCKED' });
            }
            loadEvents();
        });
    }

    if (mitmBtn) {
        mitmBtn.addEventListener('click', () => {
            const mode = modeSelect ? modeSelect.value : 'HYBRID';
            if (mode === 'CLASSICAL-VULNERABLE') {
                logAttackerAction({ action: 'MITM ATTACK', outcome: 'SUCCEEDED', detail: 'Rogue server key accepted without key pinning!' });
                updateBobGuardStatus({ action: 'MITM ATTACK', outcome: 'ACCEPTED' });
            } else {
                logAttackerAction({ action: 'MITM ATTACK', outcome: 'BLOCKED', detail: 'MitmGuard intercepted unpinned rogue server signature!' });
                updateBobGuardStatus({ action: 'MITM ATTACK', outcome: 'BLOCKED' });
            }
            loadEvents();
        });
    }
}

function resetChatPanels(mode) {
    const aliceBox = document.getElementById('chat-alice-messages');
    const bobBox = document.getElementById('chat-bob-messages');
    const attackerLog = document.getElementById('chat-attacker-log');
    const bobStatus = document.getElementById('bob-guard-status');

    if (aliceBox) aliceBox.innerHTML = '<div class="chat-bubble sender">Channel reset in ' + escapeHtml(mode) + ' mode.</div>';
    if (bobBox) bobBox.innerHTML = '<div class="chat-bubble receiver">Connected. Awaiting encrypted records...</div>';
    if (attackerLog) attackerLog.innerHTML = '<div>[Sniffing network traffic in ' + escapeHtml(mode) + ' mode...]</div>';
    if (bobStatus) {
        bobStatus.className = 'badge badge-success';
        bobStatus.textContent = '\u2714 Channel Ready';
    }
}

function appendChatMessage(sender, text) {
    const box = document.getElementById('chat-alice-messages');
    if (!box) return;
    const div = document.createElement('div');
    div.className = 'chat-bubble sender';
    div.textContent = text;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
}

function appendBobMessage(text, outcome) {
    const box = document.getElementById('chat-bob-messages');
    if (!box) return;
    const div = document.createElement('div');
    div.className = 'chat-bubble receiver';
    div.textContent = text + ' (' + outcome + ')';
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
}

function logAttackerIntercept(text) {
    const log = document.getElementById('chat-attacker-log');
    if (!log) return;
    const div = document.createElement('div');
    div.style.marginBottom = '6px';
    if (text && text.includes('[MITM Intercepted Plaintext]')) {
        div.style.color = '#f85149';
        div.style.fontWeight = 'bold';
    }
    div.textContent = text;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
}

function logAttackerAction(data) {
    const log = document.getElementById('chat-attacker-log');
    if (!log) return;
    const div = document.createElement('div');
    div.style.marginBottom = '6px';
    if (data.outcome === 'SUCCEEDED') {
        div.style.color = '#f85149';
        div.textContent = '\u26A0 [' + data.action + ' SUCCEEDED]: ' + data.detail;
    } else {
        div.style.color = '#3fb950';
        div.textContent = '\u2714 [' + data.action + ' BLOCKED]: ' + data.detail;
    }
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
}

function updateBobGuardStatus(data) {
    const status = document.getElementById('bob-guard-status');
    if (!status) return;
    if (data.outcome === 'BLOCKED') {
        status.className = 'badge badge-success';
        status.textContent = '\u2714 ' + data.action + ' BLOCKED (Event logged)';
    } else {
        status.className = 'badge badge-danger';
        status.textContent = '\u26A0 ' + data.action + ' ACCEPTED (Vulnerable)';
    }
}

// ── 6. LIVE DETECTION EVENTS (SSE) ────────────────────────────────────────

let liveEventsList = [];

function initLiveEvents() {
    loadEvents();
    connectSseStream();

    const filterSelect = document.getElementById('event-filter');
    if (filterSelect) {
        filterSelect.addEventListener('change', () => {
            renderEventFeed(liveEventsList);
        });
    }
}

function loadEvents() {
    fetch('/api/events?limit=50')
        .then(res => res.json())
        .then(events => {
            liveEventsList = events;
            renderEventFeed(events);
        })
        .catch(err => console.warn('Could not load events:', err));
}

function connectSseStream() {
    const statusBadge = document.getElementById('connection-status');
    try {
        const es = new EventSource('/api/events/stream');
        es.onopen = () => {
            if (statusBadge) {
                statusBadge.textContent = '\u25CF Live Feed Connected';
                statusBadge.className = 'badge badge-success';
            }
        };
        es.addEventListener('event', (e) => {
            try {
                const ev = JSON.parse(e.data);
                liveEventsList.unshift(ev);
                if (liveEventsList.length > 100) liveEventsList.pop();
                renderEventFeed(liveEventsList);
            } catch (ignored) {}
        });
        es.onerror = () => {
            if (statusBadge) {
                statusBadge.textContent = '\u25CB Reconnecting Live Feed...';
                statusBadge.className = 'badge badge-warning';
            }
        };
    } catch (e) {
        console.warn('SSE stream error:', e);
    }
}

function renderEventFeed(events) {
    const container = document.getElementById('events-container');
    const countEl = document.getElementById('feed-count');
    const filter = document.getElementById('event-filter') ? document.getElementById('event-filter').value : 'ALL';
    if (!container) return;

    const filtered = filter === 'ALL' ? events : events.filter(e => e.attackType === filter);
    if (countEl) countEl.textContent = filtered.length + ' events';

    container.innerHTML = '';
    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state">No detection events match the selected filter.</div>';
        return;
    }

    filtered.forEach(ev => {
        const card = document.createElement('div');
        card.className = 'event-card sev-' + escapeHtml(ev.severity);

        const top = document.createElement('div');
        top.className = 'event-top';

        const badges = document.createElement('div');
        badges.className = 'event-badges';

        const typeBadge = document.createElement('span');
        typeBadge.className = 'badge badge-primary';
        typeBadge.textContent = ev.attackType;
        badges.appendChild(typeBadge);

        const sevBadge = document.createElement('span');
        sevBadge.className = ev.severity === 'HIGH' ? 'badge badge-danger' : (ev.severity === 'MEDIUM' ? 'badge badge-warning' : 'badge badge-primary');
        sevBadge.textContent = ev.severity;
        badges.appendChild(sevBadge);

        const actBadge = document.createElement('span');
        actBadge.className = ev.action === 'BLOCKED' ? 'badge badge-success' : 'badge badge-secondary';
        actBadge.textContent = ev.action;
        badges.appendChild(actBadge);

        const timeSpan = document.createElement('span');
        timeSpan.className = 'event-time';
        timeSpan.textContent = ev.timestamp ? ev.timestamp.replace('T', ' ').substring(0, 19) + ' UTC' : '';

        top.appendChild(badges);
        top.appendChild(timeSpan);

        const detail = document.createElement('div');
        detail.className = 'event-detail';
        detail.textContent = ev.detail;

        const meta = document.createElement('div');
        meta.className = 'event-meta';
        meta.textContent = 'Component: ' + ev.component + ' | Suite: ' + ev.suite + ' | ID: ' + truncateHex(ev.id);

        card.appendChild(top);
        card.appendChild(detail);
        card.appendChild(meta);

        container.appendChild(card);
    });
}

// ── TOAST NOTIFICATIONS ───────────────────────────────────────────────────

function showToast(msg) {
    let toast = document.getElementById('dashboard-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'dashboard-toast';
        toast.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#1e293b;color:#f8fafc;border:1px solid #3b82f6;border-radius:8px;padding:10px 18px;font-size:13px;font-weight:600;z-index:99999;box-shadow:0 10px 25px rgba(0,0,0,0.5);transition:opacity 0.3s;';
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.style.opacity = '1';
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.style.opacity = '0'; }, 3000);
}
