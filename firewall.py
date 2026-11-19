
# NETWORK SECURITY AND FIREWALL MONITORING SYSTEM
# FIREWALL ENGINE MODULE

import ipaddress

# Firewall security rules
FIREWALL_RULES = [
    {"port": 80, "protocol": "TCP", "action": "ALLOW"},
    {"port": 443, "protocol": "TCP", "action": "ALLOW"},
    {"port": 53, "protocol": "UDP", "action": "ALLOW"},
    {"port": 23, "protocol": "TCP", "action": "BLOCK"}
]


def check_firewall(source_ip, destination_ip, port,
                   protocol, traffic_type):

    # Validate IP addresses
    try:
        ipaddress.ip_address(source_ip)
        ipaddress.ip_address(destination_ip)
    except ValueError:
        raise ValueError("Invalid IP address")

    protocol = protocol.upper()
    traffic_type = traffic_type.capitalize()

    if protocol not in ["TCP", "UDP"]:
        raise ValueError("Invalid protocol")

    if traffic_type not in ["Incoming", "Outgoing"]:
        raise ValueError("Invalid traffic type")

    if not 1 <= int(port) <= 65535:
        raise ValueError("Invalid port number")

    status = "BLOCKED"
    matched_rule = "DEFAULT DENY"

    for rule in FIREWALL_RULES:

        if (rule["port"] == int(port)
                and rule["protocol"] == protocol):

            matched_rule = rule["action"]
            status = (
                "ALLOWED"
                if rule["action"] == "ALLOW"
                else "BLOCKED"
            )
            break

    return {
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "Port": int(port),
        "Protocol": protocol,
        "Traffic Type": traffic_type,
        "Access Status": status,
        "Firewall Rule": matched_rule
    }


print("Firewall Engine Module Loaded Successfully")
print("Total Firewall Rules:", len(FIREWALL_RULES))
