from flask import Flask, request, render_template_string
import socket
import threading
from queue import Queue

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Port Scanner Dashboard</title>

<style>
body{
font-family: Arial;
background:#111;
color:white;
text-align:center;
}

table{
margin:auto;
border-collapse:collapse;
width:60%;
}

th,td{
border:1px solid #555;
padding:10px;
}

th{
background:#222;
}

tr:nth-child(even){
background:#1a1a1a;
}

.open{
color:lime;
}
</style>

</head>

<body>

<h1>Python Port Scanner</h1>

<form method="post">
<input type="text" name="target" placeholder="Enter domian or IP">
<button type="submit">Scan</button>
</form>

{% if results %}

<h2>Scan Results</h2>

<table>

<tr>
<th>Port</th>
<th>Status</th>
<th>Service</th>
</tr>

{% for r in results %}

<tr>
<td>{{ r.port }}</td>
<td class="open">{{ r.status }}</td>
<td>{{ r.service }}</td>
</tr>

{% endfor %}

</table>

{% endif %}

</body>
</html>
"""

def scan_ports(target):

    results = []
    queue=Queue()

    services={
        21:"FTP",
        22:"SSH",
        23:"Telnet",
        25:"SMTP",
        53:"DNS",
        80:"HTTP",
        110:"POP3",
        143:"IMAP",
        443:"HTTPS"
    }

    def scan_port(port):

        try:

            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(1)

            result=s.connect_ex((target,port))

            if result==0:

                service=services.get(port, "Unknown")

                results.append({
                    "port":port,
                    "status":"Open",
                    "service":service
                })

            s.close()

        except:
            pass

    def worker():

        while not queue.empty():

            port=queue.get()
            scan_port(port)
            queue.task_done()

    for port in range(1,1025):
        queue.put(port)

    for _ in range(100):
        t=threading.Thread(target=worker)
        t.start()

    queue.join()

    return results

@app.route("/", methods=["GET", "POST"])
def home():
    results = []

    if request.method == "POST":
        target = request.form["target"]
        target = target.replace("http://", "").replace("https://", "").split("/")[0]
        results = scan_ports(target)

    return render_template_string(HTML, results=results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
