import json

def block_ip(ip):
    print(f"[ACTION] Blocking IP: {ip}")

def isolate_container(container_id):
    print(f"[ACTION] Isolating container: {container_id}")

def send_alert(msg):
    print(f"[ALERT] {msg}")

def automated_response(alerts_file):
    with open(alerts_file, 'r') as f:
        alerts = json.load(f)
    for alert in alerts:
        if alert["type"] == "ddos":
            block_ip(alert.get("src_ip", "unknown"))
        elif alert["type"] == "compromise":
            isolate_container(alert.get("container", "unknown"))
        send_alert(f"Incident handled: {alert}")
