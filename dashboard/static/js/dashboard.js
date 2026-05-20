let protocolChart = null;

let attackChart = null;

let riskChart = null;


// ======================
// LOAD STATS
// ======================

async function loadStats() {

    const res = await fetch("/api/stats");

    const data = await res.json();


    // METRICS

    document.getElementById("totalEvents").innerText =
        data.total_events;

    document.getElementById("highAlerts").innerText =
        data.high_alerts;

    document.getElementById("lowCount").innerText =
        data.threat_counts.LOW;

    document.getElementById("mediumCount").innerText =
        data.threat_counts.MEDIUM;

    document.getElementById("highCount").innerText =
        data.threat_counts.HIGH;

    document.getElementById("criticalCount").innerText =
        data.threat_counts.CRITICAL;


    // PROTOCOL CHART

    const protocolLabels =
        Object.keys(data.protocols);

    const protocolValues =
        Object.values(data.protocols);

    if (protocolChart) {

        protocolChart.destroy();
    }

    protocolChart = new Chart(

        document.getElementById("protocolChart"),

        {

            type: "doughnut",

            data: {

                labels: protocolLabels,

                datasets: [{

                    data: protocolValues
                }]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false
            }
        }
    );


    // ATTACK CHART

    const attackLabels =
        Object.keys(data.attack_counts);

    const attackValues =
        Object.values(data.attack_counts);

    if (attackChart) {

        attackChart.destroy();
    }

    attackChart = new Chart(

        document.getElementById("attackChart"),

        {

            type: "bar",

            data: {

                labels: attackLabels,

                datasets: [{

                    label: "Attack Count",

                    data: attackValues
                }]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false
            }
        }
    );


    // RISK CHART

    const riskLabels =

        data.risk_timeline.map(

            r => {

                if (!r.time)
                    return "Unknown";

                return r.time
                    .split("T")[1]
                    ?.split(".")[0];
            }
        );

    const riskValues =

        data.risk_timeline.map(

            r => r.risk
        );

    if (riskChart) {

        riskChart.destroy();
    }

    riskChart = new Chart(

        document.getElementById("riskChart"),

        {

            type: "line",

            data: {

                labels: riskLabels,

                datasets: [{

                    label: "Risk Score",

                    data: riskValues,

                    tension: 0.3
                }]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false
            }
        }
    );
}


// ======================
// LOAD EVENTS
// ======================

async function loadEvents() {

    const res = await fetch("/api/events");

    const events = await res.json();

    const table =
        document.getElementById("eventTable");

    table.innerHTML = "";

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

        let time = "Unknown";

        if (event.timestamp) {

            try {

                time = event.timestamp
                    .split("T")[1]
                    ?.split(".")[0];

            } catch {

                time = event.timestamp;
            }
        }

        const row = `

        <tr>

            <td>
                ${event.source_ip}
            </td>

            <td>
                ${event.dns}
            </td>

            <td class="${event.threat_level.toLowerCase()}">
                ${event.threat_level}
            </td>

            <td>
                ${attacks}
            </td>

            <td>
                ${event.risk_score}
            </td>

            <td>
                ${protocol}
            </td>

            <td>
                ${time}
            </td>

            <td>
                ${event.country}
            </td>

        </tr>
        `;

        table.innerHTML += row;
    });
}


// ======================
// LOAD LOGS
// ======================

async function loadLogs() {

    try {

        const response =
            await fetch("/api/logs");

        const logs =
            await response.json();

        const container =
            document.getElementById("liveLogs");

        container.innerHTML = "";

        logs.reverse().forEach(log => {

            const div =
                document.createElement("div");

            div.className = "log-entry";

            div.innerText = log;

            container.appendChild(div);
        });

    } catch (err) {

        console.log(err);
    }
}


// ======================
// REFRESH
// ======================

async function refreshDashboard() {

    await Promise.all([

        loadStats(),

        loadEvents(),

        loadLogs()
    ]);
}


// INITIAL

refreshDashboard();


// AUTO REFRESH

setInterval(

    refreshDashboard,

    3000
);