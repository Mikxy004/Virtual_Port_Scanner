import sqlite3
from datetime import datetime
import ipaddress
from flask import Flask, request, render_template_string, send_file
import socket
import threading
from queue import Queue
import json

def init_db():
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        ip TEXT,
        port INTEGER,
        status TEXT,
        service TEXT,
        banner TEXT,
        timestamp TEXT,
        risk TEXT
    )
    """)

    conn.commit()
    conn.close()

app = Flask(__name__)

scan_progress = {"current": 0, "total":1024}
scan_results = []

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Cyber Scanner</title>

<style>
body{
background:#0d0d0d;
color:#00ff9f;
font-family:monospace;
text-align:center;
}

input,button{
padding:10px;
margin:10px;
background:black;
color:#00ff9f;
border:1px solid #00ff9f;
}

table{
margin:auto;
border-collapse:collapse;
width:70%;
}

th,td{
border:1px solid #00ff9f;
padding:10px;
}

.progress{
width:70%;
margin:auto;
border:1px solid #00ff9f;
}

.bar{
height:20px;
background:#00ff9f;
width:0%;
}

h3{
color:#00ffaa;
margin-top:30px;
}

.high {
color: red;
font-weight: bold;
}

.medium {
color: orange;
font-weight: bold;
}

.low {
color: #00ff9f;
}
</style>

<script>
function updateProgress(){
fetch("/progress")
.then(res => res.json())
.then(data => {
let percent = (data.current/data.total)*100;
document.getElementById("bar").style.width = percent + "%";
});
}

setInterval(updateProgress, 500);
</script>

</head>

<body>

<h1>Cyber Port Scanner</h1>

<form method="post">
<input name="target" placeholder="Enter target">
<button type="submit">Scan</button>
</form>

<div class="progress">
<div class="bar" id="bar"></div>
</div>

{% if history %}

<h2>Scan History</h2>

{% for timestamp, scans in history.items() %}

<h3> Scan Time: {{ timestamp }}</h3>

<table>
<tr>
<th>Target</th>
<th>IP</th>
<th>Port</th>
<th>Status</th>
<th>Service</th>
<th>Banner</th>
<th>Risk</th>
</tr>

{% for h in scans %}
<tr>
<td>{{ h[0] }}</td>
<td>{{ h[1] }}</td>
<td>{{ h[2] }}</td>
<td>{{ h[3] }}</td>
<td>{{ h[4] }}</td>
<td>{{ h[5] }}</td>
<td>
    {% set risk = h[7] if h|length > 7 else "LOW" %}

    {% if risk == "HIGH" %}
        <span class="high">🔴 HIGH</span>
    {% elif risk == "MEDIUM" %}
        <span class="medium">🟠 MEDIUM</span>
    {% else %}
        <span class="low">🟢 LOW</span>
    {% endif %}
</td>
</tr>
{% endfor %}

</table>
<br>

{% endfor %}

{% endif %}

<a href="/download">Download Report</a>


</body>
</html>
"""
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))

        try:
            banner = s.recv(1024).decode().strip()
        except:
            banner = ""

        if port in [80, 8080, 8000]:
            s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore")

        s.close()

        return banner if banner else "Unknown"

    except:
        return "Unknown"

def scan_ports(target):

    results = []
    queue=Queue()

    services={
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
        53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS"
    }

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            result = s.connect_ex((target, port))

            if result == 0:

                banner = grab_banner(target, port)

                results.append({
                    "ip": target,
                    "port": port,
                    "status": "Open",
                    "service": services.get(port,"Unknown"),
                    "banner": banner,
                    "risk": get_risk_level(port)
                })

            s.close()

        except:
           pass

    def worker():
        while not queue.empty():
            port = queue.get()
            scan_port(port)
            queue.task_done()


    for port in range(1,1025):
        queue.put(port)

    for _ in range(100):
        threading.Thread(target=worker).start()

    queue.join()

    return results

def scan_network(network):

    all_results = []
    net = ipaddress.ip_network(network, strict=False)

    for ip in net.hosts():
        ip = str(ip)

        host_results = scan_ports(ip)

        all_results.extend(host_results)

    return all_results

def get_risk_level(port):

    high_risk = [21, 23, 25, 110, 445]
    medium_risk = [22, 53, 139, 143]

    if port in high_risk:
        return "HIGH"
    elif port in medium_risk:
        return "MEDIUM"
    else:
        return "LOW"

@app.route("/", methods=["GET", "POST"])
def home():

    results = []

    if request.method == "POST":

        target = request.form["target"]
        target = target.replace("http://","").replace("https://","").split("/")[0]

        if "/" in target:
            results = scan_network(target)
        else:
            results = scan_ports(target)

        save_results(target, results)

    history = get_history()

    return render_template_string(HTML, results=results, history=history)

def save_results(target, results):

    conn = sqlite3.connect("scans.db")
    c = conn.cursor()

    scan_id = datetime.now().strftime("%Y%m%d%H%M%S")

    for r in results:
        c.execute("""
        INSERT INTO scans (target, ip, port, status, service, banner, timestamp, risk)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target,
            r.get("ip"),
            r.get("port"),
            r.get("status"),
            r.get("service"),
            r.get("banner"),
            scan_id,
            r.get("risk")
        ))

    conn.commit()
    conn.close()

def get_history():

    conn = sqlite3.connect("scans.db")
    c = conn.cursor()

    c.execute("""
    SELECT target, ip, port, status, service, banner, timestamp 
    FROM scans
    ORDER BY timestamp DESC
    """)

    rows = c.fetchall()
    conn.close()

    grouped = {}

    for row in rows:
        ts = row[6]

        if ts not in grouped:
            grouped[ts] = []

        grouped[ts].append(row)
    return grouped

@app.route("/progress")
def progress():
    return scan_progress


@app.route("/download")
def download():
    with open("report.json", "w") as f:
        json.dump(scan_results,f,indent=4)

    return send_file("report.json", as_attachment=True)


if __name__=="__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)


