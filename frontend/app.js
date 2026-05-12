document.addEventListener('DOMContentLoaded', () => {
    const uploadBtn = document.getElementById('upload-btn');
    const sampleBtn = document.getElementById('sample-btn');
    const fileInput = document.getElementById('log-upload');
    const loadingSpinner = document.getElementById('loading-spinner');
    const dashboardContent = document.getElementById('dashboard-content');
    const welcomeScreen = document.getElementById('welcome-screen');

    let apChartInstance = null;
    let authChartInstance = null;
    let ssidChartInstance = null;
    let disconnectChartInstance = null;
    let activeUsersChartInstance = null;
    let deauthTimelineInstance = null;
    let unstableClientsChartInstance = null;
    let activityTimelineInstance = null;
    let sessionDurationInstance = null;

    // Navigation logic
    const navItems = {
        'nav-dashboard': 'dashboard-content',
        'nav-threat': 'section-threat',
        'nav-health': 'section-health',
        'nav-client': 'section-client',
        'nav-ap': 'section-ap'
    };

    Object.keys(navItems).forEach(navId => {
        const navEl = document.getElementById(navId);
        if (navEl) {
            navEl.addEventListener('click', () => {
                document.querySelectorAll('nav li').forEach(li => li.classList.remove('active'));
                navEl.classList.add('active');

                if (!dashboardContent.classList.contains('hidden')) {
                    if (navId === 'nav-dashboard') {
                        document.querySelector('.main-content').scrollTo({ top: 0, behavior: 'smooth' });
                    } else {
                        const section = document.getElementById(navItems[navId]);
                        if (section) {
                            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        }
                    }
                }
            });
        }
    });

    uploadBtn.addEventListener('click', async () => {
        if (!fileInput.files.length) {
            alert('Please select a log file first.');
            return;
        }

        const file = fileInput.files[0];
        const formData = new FormData();
        formData.append('file', file);

        const startDt = document.getElementById('start-datetime').value;
        const endDt = document.getElementById('end-datetime').value;
        if (startDt) formData.append('start_datetime', startDt);
        if (endDt) formData.append('end_datetime', endDt);

        showLoading();
        try {
            const res = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            renderDashboard(data);
        } catch (err) {
            console.error(err);
            alert('Failed to analyze the log file.');
        } finally {
            hideLoading();
        }
    });

    sampleBtn.addEventListener('click', async () => {
        const startDt = document.getElementById('start-datetime').value;
        const endDt = document.getElementById('end-datetime').value;

        let url = '/api/sample';
        const params = new URLSearchParams();
        if (startDt) params.append('start_datetime', startDt);
        if (endDt) params.append('end_datetime', endDt);

        if (params.toString()) {
            url += '?' + params.toString();
        }

        showLoading();
        try {
            const res = await fetch(url);
            const data = await res.json();
            renderDashboard(data);
        } catch (err) {
            console.error(err);
            alert('Failed to load sample data. Ensure the sample file exists.');
        } finally {
            hideLoading();
        }
    });

    function showLoading() {
        loadingSpinner.classList.remove('hidden');
        dashboardContent.classList.add('hidden');
        welcomeScreen.classList.add('hidden');
    }

    function hideLoading() {
        loadingSpinner.classList.add('hidden');
    }

    function renderDashboard(data) {

        dashboardContent.classList.remove('hidden');

        renderMetrics(data);

        renderThreats(data);

        renderHealth(data);

        renderSuspects(data);

        renderCharts(data);

        // renderTimeSeriesActivity(data);

        renderSessionAnalytics(data);

        renderDeauthTimeline(
            data.deauth_windows || []
        );
    }

    function renderMetrics(data) {
        const grid = document.getElementById('metrics-grid');
        grid.innerHTML = '';

        const overview = data.overview || {};
        const apSummary = Array.isArray(data.ap_summary) ? data.ap_summary : [];
        const connectionAttempts = apSummary.length
            ? apSummary.reduce((sum, ap) => sum + (ap.total_sessions || 0), 0)
            : (overview.completed_sessions_paired || 0);

        const metrics = [
            { title: "Total Users", value: overview.unique_client_macs || 0, highlight: true },
            { title: "Active WiFi Points", value: overview.unique_aps || 0 },
            { title: "Connection Attempts", value: connectionAttempts },
            { title: "Failed Logins", value: overview.total_auth_failures || 0 }
        ];

        metrics.forEach(m => {
            grid.innerHTML += `
                <div class="metric-card ${m.highlight ? 'highlight' : ''}">
                    <div class="metric-title">${m.title}</div>
                    <div class="metric-value">${m.value}</div>
                </div>
            `;
        });
    }

    // ==================== THREAT INTEL PANEL ====================
    function renderThreats(data) {
        const grid = document.getElementById('threat-grid');
        grid.innerHTML = '';
        let threatsFound = false;

        const ov = data.overview || {};

        // 1. Deauth Storms (DoS)
        if (ov.deauth_windows_detected > 0) {
            threatsFound = true;
            grid.innerHTML += createThreatCard(
                "fa-bolt",
                "Deauth/Disassoc Storms (DoS)",
                "Bursts of deauthentication frames were detected. Attackers might be forcing clients to disconnect to capture handshakes or disrupt service.",
                ov.deauth_windows_detected + " Windows",
                true
            );
        }

        // 2. Auth Failures / Brute Force
        if (ov.clients_failed_never_succeeded > 0) {
            threatsFound = true;
            grid.innerHTML += createThreatCard(
                "fa-key",
                "Repeated Authentication Failures",
                "Multiple clients failed authentication and never succeeded. Potential password spraying or brute force attacks.",
                ov.clients_failed_never_succeeded + " Clients",
                true
            );
        }

        // 3. Rogue Events
        if (ov.rogue_events > 0) {
            threatsFound = true;
            grid.innerHTML += createThreatCard(
                "fa-user-secret",
                "Rogue Devices Detected",
                "Unauthorized Access Points or Clients were detected in the wireless environment.",
                ov.rogue_events + " Events",
                true
            );
        }

        // 4. AP Link Flaps
        const flapAps = (data.ap_summary || []).filter(ap => (ap.link_flaps || 0) > 0);
        if (flapAps.length > 0) {
            threatsFound = true;
            grid.innerHTML += createThreatCard(
                "fa-plug-circle-xmark",
                "AP Link Flaps Detected",
                "Access Points experiencing repeated link up/down events. Possible PoE, cable, or hardware issues.",
                flapAps.length + " APs affected",
                false
            );
        }

        if (!threatsFound) {
            grid.innerHTML = `<div style="color: var(--success); padding: 1rem; text-align: center;">
                <i class="fa-solid fa-check-circle"></i> No significant threats detected in this log duration.
            </div>`;
        }
    }

    function createThreatCard(icon, title, desc, countStr, isCritical) {
        const iconClass = isCritical ? '' : 'warning';
        return `
            <div class="threat-card">
                <div class="threat-icon ${iconClass}">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <div class="threat-details">
                    <h4>${title}</h4>
                    <p>${desc}</p>
                    <div class="threat-count">${countStr}</div>
                </div>
            </div>
        `;
    }

    // ==================== SUSPECTED ACTORS ====================
    function renderSuspects(data) {
        const tbody = document.querySelector('#suspects-table tbody');
        const section = document.getElementById('section-actors');
        if (!tbody || !section) return;

        tbody.innerHTML = '';
        let suspects = [];

        (data.clients || []).forEach(c => {
            let types = [];
            let reasons = [];

            // Brute Force / Dictionary Attack
            if (c.auth_failures > 30 && c.auth_successes === 0) {
                types.push('<span style="color: #f59e0b; font-weight: bold;"><i class="fa-solid fa-key"></i> Brute Force</span>');
                reasons.push(`${c.auth_failures} consecutive failed logins with 0 successes.`);
            }

            // Flooding / DoS
            if (c.total_event_count > 2000) {
                types.push('<span style="color: #ef4444; font-weight: bold;"><i class="fa-solid fa-bomb"></i> Network Flooding</span>');
                reasons.push(`Anomalously high event volume (${c.total_event_count} events).`);
            }

            // Reconnaissance / Scanning
            if (c.roam_count > 50) {
                types.push('<span style="color: #3b82f6; font-weight: bold;"><i class="fa-solid fa-satellite-dish"></i> Reconnaissance</span>');
                reasons.push(`Hopped between APs ${c.roam_count} times.`);
            }

            // Very short sessions abuse
            if (c.sessions_under_5s > 8) {
                types.push('<span style="color: #eab308; font-weight: bold;"><i class="fa-solid fa-clock"></i> Session Abuse</span>');
                reasons.push(`Multiple extremely short sessions (${c.sessions_under_5s} under 5s).`);
            }

            if (types.length > 0) {
                suspects.push({
                    mac: c.mac,
                    type: types.join('<br>'),
                    reason: reasons.join('<br>')
                });
            }
        });

        // Add AP Flaps as infrastructure-level suspects
        const flappingAps = (data.ap_summary || [])
            .filter(ap => (ap.link_flaps || 0) > 2)
            .map(ap => ({
                mac: ap.ap,
                type: '<span style="color:#ef4444;font-weight:bold;"><i class="fa-solid fa-plug-circle-xmark"></i> AP Flapping</span>',
                reason: `${ap.link_flaps} link flaps detected`
            }));

        suspects = [...suspects, ...flappingAps];

        if (suspects.length === 0) {
            section.style.display = 'none';
        } else {
            section.style.display = 'block';
            suspects.slice(0, 15).forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-family: monospace; font-size: 1.05rem; font-weight: 600;">${s.mac}</td>
                    <td>${s.type}</td>
                    <td><span style="color: #94a3b8;">${s.reason}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }
    }

    function renderHealth(data) {
        // Roaming Table
        const roamBody = document.querySelector('#roaming-table tbody');
        if (roamBody) {
            roamBody.innerHTML = '';
            const topRoams = (data.roaming_analysis?.most_common_ap_transitions || []).slice(0, 10);
            if (topRoams.length === 0) {
                roamBody.innerHTML = `<tr><td colspan="3">No roaming data available</td></tr>`;
            } else {
                topRoams.forEach(r => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${r.from_ap}</td>
                        <td>${r.to_ap}</td>
                        <td><strong>${r.count}</strong></td>
                    `;
                    roamBody.appendChild(tr);
                });
            }
        }

        // Unstable Clients Chart
        const ctxUnstable = document.getElementById('unstableClientsChart')?.getContext('2d');
        if (ctxUnstable) {
            if (unstableClientsChartInstance) unstableClientsChartInstance.destroy();
            const unstableUsers = (data.clients || [])
                .filter(c => c.sessions_under_30s > 0)
                .sort((a, b) => b.sessions_under_30s - a.sessions_under_30s)
                .slice(0, 10);

            unstableClientsChartInstance = new Chart(ctxUnstable, {
                type: 'bar',
                data: {
                    labels: unstableUsers.map(u => u.mac.substring(0, 8) + '...'),
                    datasets: [{
                        label: 'Sessions Under 30s',
                        data: unstableUsers.map(u => u.sessions_under_30s),
                        backgroundColor: '#f59e0b',
                        borderRadius: 4
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });
        }

        // Link Flaps Table
        const flapsBody = document.querySelector('#link-flaps-table tbody');
        if (flapsBody) {
            flapsBody.innerHTML = '';
            const flapsAps = (data.ap_summary || [])
                .filter(ap => (ap.link_flaps || 0) > 0)
                .sort((a, b) => b.link_flaps - a.link_flaps);

            if (flapsAps.length === 0) {
                flapsBody.innerHTML = `<tr><td colspan="2">No link flaps detected.</td></tr>`;
            } else {
                flapsAps.forEach(ap => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${ap.ap}</td>
                        <td><span style="color: #ef4444; font-weight: bold;">${ap.link_flaps}</span></td>
                    `;
                    flapsBody.appendChild(tr);
                });
            }
        }
    }

    function renderCharts(data) {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = "'Inter', sans-serif";

        // AP Events Chart
        const ctxAp = document.getElementById('apEventsChart').getContext('2d');
        if (apChartInstance) apChartInstance.destroy();
        const topAps = (data.ap_summary || []).slice(0, 10);
        apChartInstance = new Chart(ctxAp, {
            type: 'bar',
            data: {
                labels: topAps.map(ap => ap.ap.substring(0, 15)),
                datasets: [{
                    label: 'Unique Users',
                    data: topAps.map(ap => ap.unique_clients),
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }, {
                    label: 'Session Attempts',
                    data: topAps.map(ap => ap.total_sessions),
                    backgroundColor: '#8b5cf6',
                    borderRadius: 4
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        // Connection Attempt Success vs. Failure Chart
        const ctxConn = document.getElementById('connectionSuccessChart').getContext('2d');
        if (window.connectionSuccessChartInstance) window.connectionSuccessChartInstance.destroy();
        
        let totalSuccesses = 0;
        let totalFailures = data.overview?.total_auth_failures || 0;
        (data.clients || []).forEach(c => {
            totalSuccesses += (c.auth_successes || 0);
        });
        
        window.connectionSuccessChartInstance = new Chart(ctxConn, {
            type: 'doughnut',
            data: {
                labels: ['Successful Connections', 'Failed Attempts'],
                datasets: [{
                    data: [totalSuccesses, totalFailures],
                    backgroundColor: ['#10b981', '#ef4444'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        // Auth Failures Chart
        const ctxAuth = document.getElementById('authChart').getContext('2d');
        if (authChartInstance) authChartInstance.destroy();
        const topFailAps = (data.auth_failure_analysis?.per_ap || []).slice(0, 5);
        authChartInstance = new Chart(ctxAuth, {
            type: 'doughnut',
            data: {
                labels: topFailAps.map(ap => ap.ap.substring(0, 15)),
                datasets: [{
                    data: topFailAps.map(ap => ap.failures),
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        // SSID Chart
        const ctxSsid = document.getElementById('ssidChart').getContext('2d');
        if (ssidChartInstance) ssidChartInstance.destroy();
        const topSsids = (data.ssid_analysis || []).slice(0, 5);
        ssidChartInstance = new Chart(ctxSsid, {
            type: 'pie',
            data: {
                labels: topSsids.map(s => s.ssid || 'Unknown'),
                datasets: [{
                    data: topSsids.map(s => s.unique_clients),
                    backgroundColor: ['#10b981', '#3b82f6', '#8b5cf6', '#f59e0b', '#ef4444'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        // Disconnect Reasons
        const ctxDisc = document.getElementById('disconnectChart').getContext('2d');
        if (disconnectChartInstance) disconnectChartInstance.destroy();

        let reasonCounts = {};
        (data.clients || []).forEach(c => {
            if (c.deauth_disassoc_reasons) {
                Object.entries(c.deauth_disassoc_reasons).forEach(([reason, count]) => {
                    reasonCounts[reason] = (reasonCounts[reason] || 0) + count;
                });
            }
        });

        let reasons = Object.entries(reasonCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
        if (reasons.length === 0) reasons = [["No Disconnect Data", 1]];

        disconnectChartInstance = new Chart(ctxDisc, {
            type: 'doughnut',
            data: {
                labels: reasons.map(r => r[0].substring(0, 20)),
                datasets: [{
                    data: reasons.map(r => r[1]),
                    backgroundColor: ['#f59e0b', '#ef4444', '#8b5cf6', '#3b82f6', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        // Most Active Users
        const ctxActive = document.getElementById('activeUsersChart').getContext('2d');
        if (activeUsersChartInstance) activeUsersChartInstance.destroy();

        const topUsers = (data.clients || []).sort((a, b) => b.total_event_count - a.total_event_count).slice(0, 10);
        activeUsersChartInstance = new Chart(ctxActive, {
            type: 'bar',
            data: {
                labels: topUsers.map(u => u.mac.substring(0, 8) + '...'),
                datasets: [{
                    label: 'Total Activity Events',
                    data: topUsers.map(u => u.total_event_count),
                    backgroundColor: '#10b981',
                    borderRadius: 4
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }


    // function renderTimeSeriesActivity(data) {

    //     const ctx =
    //         document.getElementById(
    //             'activityTimelineChart'
    //         )?.getContext('2d');

    //     if (!ctx) return;

    //     if (activityTimelineInstance) {
    //         activityTimelineInstance.destroy();
    //     }

    //     let buckets = {};

    //     (data.clients || []).forEach(client => {

    //         (client.activity_timestamps || [])
    //             .forEach(ts => {

    //                 const d = new Date(ts);

    //                 const label =
    //                     d.getHours()
    //                         .toString()
    //                         .padStart(2, '0')
    //                     + ':00';

    //                 buckets[label] =
    //                     (buckets[label] || 0) + 1;
    //             });
    //     });

    //     if (Object.keys(buckets).length === 0) {

    //         buckets = {
    //             "00:00": 0
    //         };
    //     }

    //     const labels =
    //         Object.keys(buckets).sort();

    //     activityTimelineInstance =
    //         new Chart(ctx, {

    //             type: 'line',

    //             data: {

    //                 labels: labels,

    //                 datasets: [{
    //                     label: 'Wireless Events',

    //                     data:
    //                         labels.map(
    //                             l => buckets[l]
    //                         ),

    //                     borderColor: '#3b82f6',

    //                     backgroundColor:
    //                         'rgba(59,130,246,0.15)',

    //                     fill: true,

    //                     tension: 0.35
    //                 }]
    //             },

    //             options: {
    //                 responsive: true,
    //                 maintainAspectRatio: false
    //             }
    //         });
    // }

    function renderSessionAnalytics(data) {

        const ctx =
            document.getElementById(
                'sessionDurationChart'
            )?.getContext('2d');

        if (!ctx) return;

        if (sessionDurationInstance) {
            sessionDurationInstance.destroy();
        }

        let durations = [];

        (data.clients || []).forEach(client => {

            if (client.session_durations) {

                durations.push(
                    ...client.session_durations
                );
            }
        });

        if (durations.length === 0) {

            durations = [5, 20, 60, 300];
        }

        const buckets = {
            '<30s': 0,
            '30s-2m': 0,
            '2m-10m': 0,
            '10m-30m': 0,
            '>30m': 0
        };

        durations.forEach(sec => {

            if (sec < 30)
                buckets['<30s']++;

            else if (sec < 120)
                buckets['30s-2m']++;

            else if (sec < 600)
                buckets['2m-10m']++;

            else if (sec < 1800)
                buckets['10m-30m']++;

            else
                buckets['>30m']++;
        });

        sessionDurationInstance =
            new Chart(ctx, {

                type: 'bar',

                data: {

                    labels:
                        Object.keys(buckets),

                    datasets: [{
                        label: 'Sessions',

                        data:
                            Object.values(
                                buckets
                            ),

                        backgroundColor:
                            '#8b5cf6',

                        borderRadius: 6
                    }]
                },

                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });

        const avg =
            durations.reduce(
                (a, b) => a + b,
                0
            ) / durations.length;

        const max =
            Math.max(...durations);

        const min =
            Math.min(...durations);

        document.getElementById(
            'session-stats'
        ).innerHTML = `

            <div class="metric-card">
                <div class="metric-title">
                    Average Session
                </div>

                <div class="metric-value">
                    ${Math.round(avg)} sec
                </div>
            </div>

            <div class="metric-card" style="margin-top:1rem;">
                <div class="metric-title">
                    Longest Session
                </div>

                <div class="metric-value">
                    ${Math.round(max)} sec
                </div>
            </div>

            <div class="metric-card" style="margin-top:1rem;">
                <div class="metric-title">
                    Shortest Session
                </div>

                <div class="metric-value">
                    ${Math.round(min)} sec
                </div>
            </div>
        `;
    }

    function renderDeauthTimeline(windows) {
        // Table
        const tbody = document.querySelector('#deauth-table tbody');
        if (tbody) {
            tbody.innerHTML = '';
            windows
                .sort((a, b) => b.count_in_60s - a.count_in_60s)
                .slice(0, 25)
                .forEach(w => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${new Date(w.window_start).toLocaleString()}</td>
                        <td>${w.ap}</td>
                        <td><span style="color: #ef4444; font-weight: bold;">${w.count_in_60s}</span></td>
                        <td>${Math.round(w.duration_sec)} sec</td>
                    `;
                    tbody.appendChild(tr);
                });
        }

        // Chart
        const ctx = document.getElementById('deauthTimelineChart')?.getContext('2d');
        if (!ctx) return;

        if (deauthTimelineInstance) deauthTimelineInstance.destroy();

        const topWindows = windows
            .sort((a, b) => new Date(a.window_start) - new Date(b.window_start))
            .slice(0, 50);

        deauthTimelineInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: topWindows.map(w => new Date(w.window_start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })),
                datasets: [{
                    label: 'Deauth Events / 60s',
                    data: topWindows.map(w => w.count_in_60s),
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239,68,68,0.15)',
                    fill: true,
                    tension: 0.35,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    tooltip: {
                        callbacks: {
                            afterLabel: function (context) {
                                const w = topWindows[context.dataIndex];
                                return [`AP: ${w.ap}`, `Duration: ${Math.round(w.duration_sec)} sec`];
                            }
                        }
                    }
                },
                scales: {
                    x: { ticks: { maxRotation: 45, minRotation: 45 } },
                    y: { beginAtZero: true, title: { display: true, text: 'Events' } }
                }
            }
        });
    }
});