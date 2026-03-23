import ipaddress
from flask import Flask, request, render_template_string, send_file
import socket
import threading
from queue import Queue
import json

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

{% if results %}

<h2>Results</h2>

<table>

<tr>
<th>IP Address</th>
<th>Port</th>
<th>Status</th>
<th>Service</th>
<th>Banner</th>
</tr>

{% for r in results %}
<tr>
<td>{{ r.ip }}</td>
<td>{{ r.port }}</td>
<td>{{ r.status }}</td>
<td>{{ r.service }}</td>
<td>{{ r.banner }}</td>
</tr>
{% endfor %}

</table>

<br>
<a href="/download">Download Report</a>

{% endif %}

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
                    "banner": banner[:50]
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

    return render_template_string(HTML, results=results)


@app.route("/progress")
def progress():
    return scan_progress


@app.route("/download")
def download():
    with open("report.json", "w") as f:
        json.dump(scan_results,f,indent=4)

    return send_file("report.json", as_attachment=True)


if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)


