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

    // Navigation logic
    const navItems = {
        'nav-dashboard': 'dashboard-content',
        'nav-threat': 'section-threat',
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
        
        renderMetrics(data.overview);
        renderThreats(data.overview);
        renderSuspects(data.clients);
        renderCharts(data);
    }

    function renderMetrics(overview) {
        const grid = document.getElementById('metrics-grid');
        grid.innerHTML = '';
        
        const metrics = [
            { title: "Total Users", value: overview.unique_client_macs, highlight: true },
            { title: "Active WiFi Points", value: overview.unique_aps },
            { title: "Total Connections", value: overview.completed_sessions_paired },
            { title: "Failed Logins", value: overview.total_auth_failures }
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

    function renderThreats(overview) {
        const grid = document.getElementById('threat-grid');
        grid.innerHTML = '';
        let threatsFound = false;

        // Threat 1: Deauth Storms (DoS)
        if (overview.deauth_windows_detected > 0) {
            threatsFound = true;
            grid.innerHTML += createThreatCard(
                "fa-bolt", 
                "Deauth/Disassoc Storms (DoS)", 
                "Bursts of deauthentication frames were detected. Attackers might be forcing clients to disconnect to capture handshakes or disrupt service.",
                overview.deauth_windows_detected + " Windows",
                true
            );
        }

        // Threat 2: Auth Failures / Brute Force
        if (overview.clients_failed_never_succeeded > 0) {
            threatsFound = true;
            grid.innerHTML += createThreatCard(
                "fa-key", 
                "Repeated Authentication Failures", 
                "Multiple clients failed authentication and never succeeded. Potential password spraying or brute force attacks.",
                overview.clients_failed_never_succeeded + " Clients",
                false
            );
        }

        if (!threatsFound) {
            grid.innerHTML = `<div style="color: var(--success); padding: 1rem;"><i class="fa-solid fa-check-circle"></i> No significant threats detected in this log duration.</div>`;
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

    function renderCharts(data) {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = "'Inter', sans-serif";
        
        // 1. AP Events Chart
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
                    label: 'Total Connections',
                    data: topAps.map(ap => ap.total_sessions),
                    backgroundColor: '#8b5cf6',
                    borderRadius: 4
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        // 2. Auth Chart (Failed Logins)
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

        // 3. Top WiFi Networks (SSIDs)
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

        // 4. Why Users Disconnected
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
        
        let reasons = Object.entries(reasonCounts).sort((a,b) => b[1] - a[1]).slice(0, 5);
        if (reasons.length === 0) {
            reasons = [["No Disconnect Data", 1]];
        }
        
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

        // 5. Most Active Users
        const ctxActive = document.getElementById('activeUsersChart').getContext('2d');
        if (activeUsersChartInstance) activeUsersChartInstance.destroy();
        
        const topUsers = (data.clients || []).sort((a,b) => b.total_event_count - a.total_event_count).slice(0, 10);
        activeUsersChartInstance = new Chart(ctxActive, {
            type: 'bar',
            data: {
                labels: topUsers.map(u => u.mac),
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

    function renderSuspects(clients) {
        const tbody = document.querySelector('#suspects-table tbody');
        const section = document.getElementById('section-actors');
        if (!tbody || !section) return;
        
        tbody.innerHTML = '';
        let suspects = [];

        (clients || []).forEach(c => {
            let types = [];
            let reasons = [];

            // Rule 1: Brute Force / Dictionary Attack
            if (c.auth_failures > 50 && c.auth_successes === 0) {
                types.push('<span style="color: #f59e0b; font-weight: bold;"><i class="fa-solid fa-key"></i> Brute Force</span>');
                reasons.push(`${c.auth_failures} consecutive failed logins with 0 successes.`);
            }

            // Rule 2: Flooding / DoS
            if (c.total_event_count > 3000) {
                types.push('<span style="color: #ef4444; font-weight: bold;"><i class="fa-solid fa-bomb"></i> Network Flooding</span>');
                reasons.push(`Anomalously high event volume (${c.total_event_count} events).`);
            }

            // Rule 3: Reconnaissance / Scanning
            if (c.roam_count > 60) {
                types.push('<span style="color: #3b82f6; font-weight: bold;"><i class="fa-solid fa-satellite-dish"></i> Reconnaissance</span>');
                reasons.push(`Hopped between APs ${c.roam_count} times in a short duration.`);
            }

            if (types.length > 0) {
                suspects.push({
                    mac: c.mac,
                    type: types.join('<br>'),
                    reason: reasons.join('<br>')
                });
            }
        });

        if (suspects.length === 0) {
            section.style.display = 'none';
        } else {
            section.style.display = 'block';
            // Show up to top 15 suspects
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
});
