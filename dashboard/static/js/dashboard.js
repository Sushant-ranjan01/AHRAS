let protocolChart = null;


// -----------------------------------
// LOAD STATS
// -----------------------------------
async function loadStats() {

    const res = await fetch("/api/stats");

    const data = await res.json();

    document.getElementById("totalEvents").innerText =
        data.total_events;

    document.getElementById("highAlerts").innerText =
        data.high_alerts;

    const protocols = data.protocols;

    const labels = Object.keys(protocols);

    const values = Object.values(protocols);

    if (protocolChart) {
        protocolChart.destroy();
    }

    protocolChart = new Chart(
        document.getElementById("protocolChart"),
        {
            type: "doughnut",

            data: {

                labels: labels,

                datasets: [{
                    data: values
                }]
            }
        }
    );
}


// -----------------------------------
// LOAD EVENTS
// -----------------------------------
async function loadEvents() {

    const res = await fetch("/api/events");

    const events = await res.json();

    const table = document.getElementById("eventTable");

    table.innerHTML = "";

    const logContainer =
        document.getElementById("liveLogs");

    logContainer.innerHTML = "";

    events.forEach(event => {

        let protocol = "OTHER";

        if (event.protocol === 6)
            protocol = "TCP";

        else if (event.protocol === 17)
            protocol = "UDP";

        else if (event.protocol === 1)
            protocol = "ICMP";

        const attacks =
            event.attack_types.length > 0
            ? event.attack_types.join(", ")
            : "Normal";

        const timestamp =
            event.timestamp.includes("T")
            ? event.timestamp.split("T")[1].split(".")[0]
            : event.timestamp;

        // --------------------------------
        // TABLE ROW
        // --------------------------------
        const row = `

            <tr>

                <td>${timestamp}</td>

                <td>${event.source_ip}</td>

                <td>${event.dns}</td>

                <td>${event.country}</td>

                <td>${protocol}</td>

                <td>${attacks}</td>

                <td>${event.risk_score}</td>

                <td class="${event.threat_level.toLowerCase()}">
                    ${event.threat_level}
                </td>

            </tr>
        `;

        table.innerHTML += row;

        // --------------------------------
        // LIVE LOGS
        // --------------------------------
        const log = `

            <div class="log-entry">

                <b>[${event.threat_level}]</b>

                ${event.source_ip}

                | ${protocol}

                | Risk=${event.risk_score}

                | ${attacks}

            </div>
        `;

        logContainer.innerHTML += log;
    });
}


// -----------------------------------
// REFRESH
// -----------------------------------
async function refreshDashboard() {

    await loadStats();

    await loadEvents();
}


// -----------------------------------
// INITIAL LOAD
// -----------------------------------
refreshDashboard();


// -----------------------------------
// AUTO REFRESH
// -----------------------------------
setInterval(async () => {

    await refreshDashboard();

}, 3000);