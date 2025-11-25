import json
import nmap
from datetime import datetime

# Load rules
with open("rules.json") as f:
    RULES = json.load(f)

scanner = nmap.PortScanner()

# Ask user for target
target = input("Enter target IP or subnet (example: 192.168.1.0/24): ")
print(f"\nScanning {target}...\n")

# Perform scan
scanner.scan(hosts=target, arguments="-sV")

results = {}

for host in scanner.all_hosts():
    host_data = {
        "ip": host,
        "state": scanner[host].state(),
        "ports": [],
        "alerts": []
    }

    if "tcp" in scanner[host]:
        for port in scanner[host]["tcp"]:
            port_data = scanner[host]["tcp"][port]
            service = port_data.get("name", "")
            version = port_data.get("version", "")

            host_data["ports"].append({
                "port": port,
                "state": port_data.get("state", ""),
                "service": service,
                "version": version
            })

            for rule in RULES:
                match_port = ("port" in rule and rule["port"] == port)
                match_service = ("service" in rule and rule["service"].lower() in service.lower())

                if match_port or match_service:
                    host_data["alerts"].append({
                        "message": rule["message"],
                        "severity": rule["severity"],
                        "score": rule["score"]
                    })

    results[host] = host_data

# Display results with severity
for host, data in results.items():
    print(f"\n=== Host: {data['ip']} ({data['state']}) ===")

    for p in data["ports"]:
        print(f"Port {p['port']}: {p['service']} {p['version']}")

    if data["alerts"]:
        print("\nAlerts:")
        for a in data["alerts"]:
            print(f" - {a['message']}  | Severity: {a['severity'].upper()}  | Score: {a['score']}")
    else:
        print("\nNo critical alerts found.")

# Save result JSON
summary = {
    "scanned_at": datetime.utcnow().isoformat() + "Z",
    "target": target,
    "hosts": list(results.values())
}

with open("scan_results.json", "w", encoding="utf-8") as jf:
    json.dump(summary, jf, indent=2, ensure_ascii=False)

print("\nSaved scan results to scan_results.json")
