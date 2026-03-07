import socket
import threading
from queue import Queue

target = input("Enter target IP or domain: ")

target = target.replace("http://", "").replace("https://", "").split("/")[0]

print(f"\nScanning {target}...\n")

queue = Queue()



def grab_banner(s):
    try:
        banner = s.recv(1024).decode().strip()
        return banner
    except:
        return "Unknown Service"


def scan_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        result = s.connect_ex((target, port))

        if result == 0:
            banner = grab_banner(s)
            print(f"port {port} OPEN - {banner}")

        s.close()

    except:
         pass


def worker():
    while not queue.empty():
        port = queue.get()
        scan_port(port)
        queue.task_done()


for port in range(1, 1025):
    queue.put(port)


for t in range(100):
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()


queue.join()

print("\nScan completed!")
