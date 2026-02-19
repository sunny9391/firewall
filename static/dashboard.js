document.addEventListener('DOMContentLoaded', () => {
    const fetchDashboardData = async () => {
        try {
            const response = await fetch('/api/dashboard_data');
            const data = await response.json();

            // Populate summary cards
            document.getElementById('totalRequests').textContent = data.totalRequests;
            document.getElementById('blockedRequests').textContent = data.blockedRequests;
            document.getElementById('mlAnomalies').textContent = data.mlAnomalies;
            
            // Populate top IPs list
            const topIpsList = document.getElementById('topIpsList');
            topIpsList.innerHTML = ''; // Clear existing list
            data.topIps.forEach(item => {
                const li = document.createElement('li');
                li.textContent = `${item.ip}: ${item.count} attacks`;
                topIpsList.appendChild(li);
            });

            // Populate top URLs list
            const topUrlsList = document.getElementById('topUrlsList');
            topUrlsList.innerHTML = ''; // Clear existing list
            data.topUrls.forEach(item => {
                const li = document.createElement('li');
                li.textContent = `${item.url}: ${item.count} attacks`;
                topUrlsList.appendChild(li);
            });
            
            // Populate live logs
            const liveLogsList = document.getElementById('liveLogs');
            liveLogsList.innerHTML = ''; // Clear existing list
            data.liveLogs.reverse().forEach(log => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span class="${log.status}">${log.status.toUpperCase()}</span> 
                    <span>${log.timestamp} - ${log.method} ${log.path}</span>
                `;
                liveLogsList.appendChild(li);
            });

        } catch (error) {
            console.error("Failed to fetch dashboard data:", error);
        }
    };

    fetchDashboardData();
    // Refresh data every 5 seconds
    setInterval(fetchDashboardData, 5000); 
});