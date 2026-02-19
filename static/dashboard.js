document.addEventListener('DOMContentLoaded', () => {
    const setList = (elementId, items, formatter, emptyText) => {
        const element = document.getElementById(elementId);
        element.innerHTML = '';

        if (!items || items.length === 0) {
            const empty = document.createElement('li');
            empty.textContent = emptyText;
            element.appendChild(empty);
            return;
        }

        items.forEach((item) => {
            const li = document.createElement('li');
            li.textContent = formatter(item);
            element.appendChild(li);
        });
    };

    const renderHealth = (blockedRequests, totalRequests) => {
        const ratio = totalRequests === 0 ? 0 : Math.round((blockedRequests / totalRequests) * 100);
        const fill = document.getElementById('healthFill');
        const label = document.getElementById('healthLabel');

        fill.style.width = `${Math.min(ratio, 100)}%`;
        if (ratio >= 40) {
            label.textContent = 'High threat pressure detected. Tighten filtering and review active attack vectors.';
        } else if (ratio >= 15) {
            label.textContent = 'Moderate risk detected. Continue monitoring and tune signatures.';
        } else {
            label.textContent = 'Threat level is stable. No critical pressure detected.';
        }
    };

    const renderLogs = (logs) => {
        const liveLogsList = document.getElementById('liveLogs');
        liveLogsList.innerHTML = '';

        if (!logs || logs.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No events recorded yet.';
            liveLogsList.appendChild(li);
            return;
        }

        [...logs].reverse().forEach((log) => {
            const li = document.createElement('li');
            const statusClass = (log.status || '').toLowerCase();
            li.innerHTML = `
                <span class="log-status ${statusClass}">${log.status}</span>
                <span>${log.timestamp} · ${log.method} ${log.path} · ${log.reason}</span>
            `;
            liveLogsList.appendChild(li);
        });
    };

    const fetchDashboardData = async () => {
        try {
            const response = await fetch('/api/dashboard_data');
            const data = await response.json();

            const totalRequests = data.totalRequests || 0;
            const blockedRequests = data.blockedRequests || 0;
            const mlAnomalies = data.mlAnomalies || 0;
            const blockRate = totalRequests === 0 ? 0 : ((blockedRequests / totalRequests) * 100).toFixed(1);

            document.getElementById('totalRequests').textContent = totalRequests;
            document.getElementById('blockedRequests').textContent = blockedRequests;
            document.getElementById('mlAnomalies').textContent = mlAnomalies;
            document.getElementById('blockRate').textContent = `${blockRate}%`;
            document.getElementById('lastUpdated').textContent = `Last updated: ${new Date().toLocaleTimeString()}`;

            setList('topIpsList', data.topIps, (item) => `${item.ip}: ${item.count} events`, 'No attack IP data yet.');
            setList('topUrlsList', data.topUrls, (item) => `${item.url}: ${item.count} hits`, 'No targeted URL data yet.');
            renderLogs(data.liveLogs);
            renderHealth(blockedRequests, totalRequests);
        } catch (error) {
            console.error('Failed to fetch dashboard data:', error);
        }
    };

    fetchDashboardData();
    setInterval(fetchDashboardData, 5000);
});
