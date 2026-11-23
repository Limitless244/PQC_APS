/**
 * PQC-APS Dashboard JavaScript Client
 * Handles tab navigation, REST API interactions, SSE live streaming,
 * Chart.js benchmark visualizations, and safe HTML rendering.
 */

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initAttackMatrix();
    initLiveEvents();
    initBenchmarks();
    initScanner();
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

// ── TABS ──────────────────────────────────────────────────────────────────

function initTabs() {
    const buttons = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');

    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-tab');
            buttons.forEach(b => b.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetEl = document.getElementById('tab-' + target);
            if (targetEl) targetEl.classList.add('active');

            if (target === 'benchmarks') {
                renderAllCharts();
            }
        });
    });
}

// ── ATTACK MATRIX ─────────────────────────────────────────────────────────

let attackMatrixData = [];

function initAttackMatrix() {
    loadAttackMatrix();

    const runBtn = document.getElementById('btn-run-attacks');
    if (runBtn) {
        runBtn.addEventListener('click', () => {
            runBtn.disabled = true;
            runBtn.textContent = 'Running Matrix On Localhost...';
            fetch('/api/demo/run-attacks', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    attackMatrixData = data;
                    renderAttackMatrix(data);
                    loadEvents(); // Also refresh events feed
                })
                .catch(err => {
                    console.error('Failed to run attack matrix:', err);
                    alert('Error executing local attack matrix: ' + err.message);
                })
                .finally(() => {
                    runBtn.disabled = false;
                    runBtn.innerHTML = '&#x25B6; Run Local Attack Matrix';
                });
        });
    }

    const closeBtn = document.getElementById('btn-close-drawer');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            document.getElementById('matrix-detail-drawer').classList.add('hidden');
        });
    }
}

function loadAttackMatrix() {
    fetch('/api/attacks')
        .then(res => {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.json();
        })
        .then(data => {
            attackMatrixData = data;
            renderAttackMatrix(data);
        })
        .catch(err => {
            console.warn('Could not load attacks, retrying:', err);
        });
}

function renderAttackMatrix(matrix) {
    const tbody = document.getElementById('attack-matrix-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    const attacks = ['Downgrade', 'MITM', 'Replay', 'Nonce Reuse', 'Tampering'];
    const modes = ['CLASSICAL-VULNERABLE', 'CLASSICAL-HARDENED', 'HYBRID'];

    attacks.forEach(atk => {
        const tr = document.createElement('tr');
        const th = document.createElement('td');
        th.style.fontWeight = '600';
        th.textContent = atk;
        tr.appendChild(th);

        modes.forEach(mode => {
            const td = document.createElement('td');
            const item = matrix.find(m => m.attack.toLowerCase() === atk.toLowerCase() && m.mode === mode);
            if (item) {
                const badge = document.createElement('span');
                badge.className = item.attackSucceeded ? 'badge badge-danger' : 'badge badge-success';
                badge.textContent = item.attackSucceeded ? 'SUCCEEDED' : 'BLOCKED';
                td.appendChild(badge);
                td.addEventListener('click', () => showCellDetails(item));
            } else {
                td.textContent = 'N/A';
            }
            tr.appendChild(td);
        });

        tbody.appendChild(tr);
    });
}

function showCellDetails(item) {
    const drawer = document.getElementById('matrix-detail-drawer');
    if (!drawer) return;

    document.getElementById('detail-attack').textContent = item.attack;
    document.getElementById('detail-mode').textContent = item.mode;

    const outcomeEl = document.getElementById('detail-outcome');
    outcomeEl.textContent = item.attackSucceeded ? 'Attack Succeeded (Vulnerable Baseline)' : 'Attack Blocked (Defence Active)';
    outcomeEl.className = item.attackSucceeded ? 'field-val text-danger font-bold' : 'field-val text-success font-bold';

    document.getElementById('detail-event-id').textContent = item.eventId || 'None (Vulnerable unmonitored baseline)';
    document.getElementById('detail-evidence').textContent = item.detail;

    drawer.classList.remove('hidden');
    drawer.scrollIntoView({ behavior: 'smooth' });
}

// ── LIVE EVENTS (SSE) ─────────────────────────────────────────────────────

let allEvents = [];

function initLiveEvents() {
    loadEvents();
    connectSseStream();

    const filterSelect = document.getElementById('event-filter');
    if (filterSelect) {
        filterSelect.addEventListener('change', () => {
            renderEventFeed(allEvents);
        });
    }
}

function loadEvents() {
    fetch('/api/events?limit=50')
        .then(res => res.json())
        .then(events => {
            allEvents = events;
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
                statusBadge.textContent = '● Live Feed Connected';
                statusBadge.className = 'badge badge-success';
            }
        };
        es.addEventListener('event', (e) => {
            try {
                const ev = JSON.parse(e.data);
                allEvents.unshift(ev);
                if (allEvents.length > 100) allEvents.pop();
                renderEventFeed(allEvents);
            } catch (ignored) {}
        });
        es.onerror = () => {
            if (statusBadge) {
                statusBadge.textContent = '○ Reconnecting Live Feed...';
                statusBadge.className = 'badge badge-warning';
            }
        };
    } catch (e) {
        console.warn('SSE not supported or failed:', e);
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
        container.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted)">No detection events match the selected filter.</div>';
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
        typeBadge.className = 'badge badge-info';
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

// ── BENCHMARKS & CHART.JS ─────────────────────────────────────────────────

let benchmarkData = null;
let charts = {};

function initBenchmarks() {
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
}

function loadBenchmarks(onComplete) {
    fetch('/api/benchmarks')
        .then(res => res.json())
        .then(data => {
            benchmarkData = data;
            renderBenchmarkHeader(data.machine, data.summary);
            renderAllCharts();
        })
        .catch(err => console.warn('Could not load benchmarks:', err))
        .finally(() => {
            if (onComplete) onComplete();
        });
}

function renderBenchmarkHeader(machine, summary) {
    const hdr = document.getElementById('machine-info-header');
    if (hdr && machine) {
        hdr.textContent = 'Host Environment: ' + machine.jdkVersion + ' (' + machine.jvmName + ') | ' +
            machine.osName + ' ' + machine.osArch + ' | ' + machine.cpuCores + ' CPU Cores';
    }
    const cpuLimitation = document.getElementById('cpu-limitation-text');
    if (cpuLimitation && summary) {
        cpuLimitation.textContent = summary.analysis;
    }
}

function renderAllCharts() {
    if (!benchmarkData) return;
    renderSizesChart(benchmarkData.sizes);
    renderWireChart(benchmarkData.sizes);
    renderLatencyChart(benchmarkData.latency);
    renderThroughputChart(benchmarkData.throughput);
    renderCpuChart(benchmarkData.cpu);
}

function renderSizesChart(sizes) {
    const canvas = document.getElementById('chart-sizes');
    if (!canvas) return;

    const prims = sizes.filter(s => s.category === 'PRIMITIVE_KEY' || s.category === 'SIGNATURE');
    const labels = prims.map(s => s.item);
    const rawData = prims.map(s => s.rawBytes);
    const encData = prims.map(s => s.encodedBytes);

    if (window.Chart) {
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
                scales: { y: { beginAtZero: true, grid: { color: '#30363d' } }, x: { grid: { display: false } } },
                plugins: { legend: { labels: { color: '#c9d1d9' } } }
            }
        });
    } else {
        renderTableFallback('fallback-sizes', canvas, labels, rawData, 'Bytes');
    }
}

function renderWireChart(sizes) {
    const canvas = document.getElementById('chart-wire');
    if (!canvas) return;

    const wire = sizes.filter(s => s.category === 'TOTAL_HANDSHAKE');
    const labels = wire.map(s => s.suite);
    const totals = wire.map(s => s.rawBytes);

    if (window.Chart) {
        if (charts['wire']) charts['wire'].destroy();
        charts['wire'] = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Total Handshake Wire Size (Bytes)',
                        data: totals,
                        backgroundColor: ['#3fb950', '#d29922', '#58a6ff']
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } },
                plugins: { legend: { labels: { color: '#c9d1d9' } } }
            }
        });
    } else {
        renderTableFallback('fallback-wire', canvas, labels, totals, 'Bytes');
    }
}

function renderLatencyChart(latency) {
    const canvas = document.getElementById('chart-latency');
    if (!canvas) return;

    const handshakes = latency.filter(l => l.operation === 'handshake');
    const labels = handshakes.map(h => h.suiteOrAlgorithm);
    const avg = handshakes.map(h => h.avgMicroseconds);
    const p95 = handshakes.map(h => h.p95Microseconds);

    if (window.Chart) {
        if (charts['latency']) charts['latency'].destroy();
        charts['latency'] = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    { label: 'Avg Latency (µs)', data: avg, backgroundColor: '#3fb950' },
                    { label: 'P95 Latency (µs)', data: p95, backgroundColor: '#f85149' }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } },
                plugins: { legend: { labels: { color: '#c9d1d9' } } }
            }
        });
    } else {
        renderTableFallback('fallback-latency', canvas, labels, avg, 'µs');
    }
}

function renderThroughputChart(throughput) {
    const canvas = document.getElementById('chart-throughput');
    if (!canvas) return;

    const labels = throughput.map(t => t.recordSize + ' ' + t.operation);
    const rates = throughput.map(t => t.throughputMBps);

    if (window.Chart) {
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
                scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } },
                plugins: { legend: { labels: { color: '#c9d1d9' } } }
            }
        });
    } else {
        renderTableFallback('fallback-throughput', canvas, labels, rates, 'MB/s');
    }
}

function renderCpuChart(cpuList) {
    const canvas = document.getElementById('chart-cpu');
    if (!canvas) return;

    const labels = cpuList.map(c => c.suite);
    const cpuValues = cpuList.map(c => c.avgCpuMicroseconds);

    if (window.Chart) {
        if (charts['cpu']) charts['cpu'].destroy();
        charts['cpu'] = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{ label: 'Thread CPU Time (µs / Handshake)', data: cpuValues, backgroundColor: '#58a6ff' }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true, grid: { color: '#30363d' } } },
                plugins: { legend: { labels: { color: '#c9d1d9' } } }
            }
        });
    } else {
        renderTableFallback('fallback-cpu', canvas, labels, cpuValues, 'µs');
    }
}

function renderTableFallback(containerId, canvas, labels, data, unit) {
    canvas.style.display = 'none';
    const container = document.getElementById(containerId);
    if (!container) return;
    container.classList.remove('hidden');
    let html = '<table style="width:100%; border-collapse:collapse;">';
    for (let i = 0; i < labels.length; i++) {
        html += '<tr style="border-bottom:1px solid #30363d;"><td style="padding:4px 8px;">' +
            escapeHtml(labels[i]) + '</td><td style="text-align:right; font-weight:600; padding:4px 8px;">' +
            data[i] + ' ' + unit + '</td></tr>';
    }
    html += '</table>';
    container.innerHTML = html;
}

// ── CRYPTO SCANNER ────────────────────────────────────────────────────────

function initScanner() {
    loadScanReport('vulnerable');

    const pills = document.querySelectorAll('.pill-btn');
    pills.forEach(pill => {
        pill.addEventListener('click', () => {
            pills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            const target = pill.getAttribute('data-target');
            loadScanReport(target);
        });
    });
}

function loadScanReport(target) {
    fetch('/api/scan/' + target)
        .then(res => {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.json();
        })
        .then(report => {
            renderScanReport(report, target);
        })
        .catch(err => {
            console.warn('Could not load scan report for ' + target + ':', err);
        });
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
        scoreEl.className = summary.overallScore >= 70 ? 'metric-value text-danger' : (summary.overallScore >= 40 ? 'metric-value text-warning' : 'metric-value text-success');
    }
    if (gradeEl) {
        gradeEl.textContent = summary.grade;
        gradeEl.className = summary.grade === 'F' ? 'metric-value text-danger' : (summary.grade === 'A' ? 'metric-value text-success' : 'metric-value text-primary');
    }
    if (targetDescEl) {
        targetDescEl.textContent = target === 'vulnerable' ? 'Legacy Classical Application' : (target === 'migrated' ? 'Post-Quantum Migrated App' : 'PQC-APS Repository');
    }
    if (statusDescEl) {
        statusDescEl.textContent = summary.overallScore === 0 ? 'Quantum-Safe' : 'Migration Required';
    }
    if (highCountEl) {
        const counts = summary.countsBySeverity || {};
        const critAndHigh = (counts.CRITICAL || 0) + (counts.HIGH || 0);
        highCountEl.textContent = critAndHigh;
    }
    if (totalCountEl) {
        totalCountEl.textContent = summary.totalFindings;
    }

    const tbody = document.getElementById('scanner-findings-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!report.findings || report.findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-muted)">Zero cryptographic vulnerabilities detected. Clean quantum-safe baseline!</td></tr>';
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
        badge.className = f.severity === 'CRITICAL' ? 'badge badge-danger' : (f.severity === 'HIGH' ? 'badge badge-danger' : (f.severity === 'MEDIUM' ? 'badge badge-warning' : 'badge badge-info'));
        badge.textContent = f.severity;
        tdSev.appendChild(badge);

        const tdMatched = document.createElement('td');
        tdMatched.className = 'font-mono';
        tdMatched.textContent = f.algorithm || f.redactedSnippet;

        const tdCat = document.createElement('td');
        tdCat.textContent = f.category;

        const tdScore = document.createElement('td');
        tdScore.style.fontWeight = '600';
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
