from flask import Flask, request, jsonify
import threading
import uuid
import os
import time
import base64
from datetime import datetime, timedelta
import json
import requests
import sys

app = Flask(__name__)

# In-memory data structures
users = {}
traffic_logs = {}
domains = {}
client_sub_ips = {}
isps = {}
lock = threading.Lock()
config = {}
last_loaded_config = {}
unknown_isps = {}

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "port": 7080,
    "host": "0.0.0.0",
    "subIPPrefix": "10.0.",
    "inactivity_limit_days": 3,
    "check_config_interval_seconds": 60,
    "adminUsername": "admin",
    "adminPassword": "admin"
}
# Helper functions for Base64 encoding/decoding
def base64_encode(data):
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")

def base64_decode(data):
    try:
        return base64.b64decode(data).decode("utf-8")
    except Exception as e:
        print(f"[ERROR] Failed to decode Base64: {str(e)}")
        return ""
def encode_domain(domain):
    return base64_encode(domain)

def decode_domain(encoded_domain):
    return base64_decode(encoded_domain)

# Configuration management
def load_config():
    global config, last_loaded_config

    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as file:
                try:
                    new_config = json.load(file)
                    if new_config != last_loaded_config:
                        print(f"[INFO] Configuration updated: {new_config}")
                        last_loaded_config = new_config.copy()

                        # Handle Sub-IP Prefix Change
                        if new_config.get("subIPPrefix") != config.get("subIPPrefix"):
                            print(f"[INFO] Sub-IP Prefix changed from {config.get('subIPPrefix')} to {new_config.get('subIPPrefix')}")
                            config["subIPPrefix"] = new_config.get("subIPPrefix", "10.0.").strip()
                            handle_subip_prefix_conflicts(config["subIPPrefix"])

                        # Update only changed fields to preserve existing valid configuration
                        for key, value in new_config.items():
                            if key != "subIPPrefix":  # Already handled above
                                config[key] = value
                            print(f"Config: {key}: {value}")

                        # Restart server for critical changes (port or host)
                        if (
                            new_config.get("port") != config.get("port") or 
                            new_config.get("host") != config.get("host")
                        ):
                            print("[INFO] Critical configuration change detected. Restarting the server...")
                            restart_server()
                except json.JSONDecodeError:
                    print("[ERROR] Malformed configuration file. Using last known configuration.")
        else:
            # If no configuration file exists, create a default one
            print("[INFO] Config file not found. Creating default configuration.")
            config.update(DEFAULT_CONFIG)
            last_loaded_config = config.copy()
            with open(CONFIG_FILE, "w") as file:
                json.dump(DEFAULT_CONFIG, file, indent=4)
            print("[INFO] Default configuration created.")
    except Exception as e:
        print(f"[ERROR] Unexpected error while loading configuration: {str(e)}")

def handle_subip_prefix_conflicts(new_subip_prefix):
    """
    Handle Sub-IP Prefix conflicts with known ISPs.
    Notify ISPs to update their Sub-IP Prefix if there's a conflict.
    """
    print(f"[INFO] Checking for conflicts with Sub-IP Prefix: {new_subip_prefix}")

    conflicting_isps = {
        isp_id: isp for isp_id, isp in isps.items()
        if isp["subIPPrefix"] == new_subip_prefix
    }

    for isp_id, isp_details in conflicting_isps.items():
        print(f"[WARNING] Conflict detected with ISP {isp_id} for Sub-IP Prefix {new_subip_prefix}. Notifying ISP...")
        try:
            response = requests.post(
                f"http://{isp_details['realIP']}:{isp_details['port']}/isp/update_subip",
                json={"message": f"Sub-IP Prefix conflict detected with prefix {new_subip_prefix}. Please update your prefix."}
            )
            if response.status_code == 200:
                print(f"[INFO] Successfully notified ISP {isp_id} about the conflict.")
            else:
                print(f"[ERROR] Failed to notify ISP {isp_id}. HTTP Status Code: {response.status_code}")
        except Exception as e:
            print(f"[ERROR] Exception while notifying ISP {isp_id}: {str(e)}")
        
def restart_server():
    """Restart the Flask server."""
    print("[INFO] Restarting server...")
    os.execv(sys.executable, [sys.executable] + sys.argv)

# Load users from file on startup
def load_users_from_file():
    if not os.path.exists("users.txt"):
        print("[INFO] No users file found, starting fresh.")
        return

    with open("users.txt", "r") as file:
        for line in file:
            parts = line.strip().split(",")
            if len(parts) == 5:
                username, password, real_ip, sub_ip, user_id = parts
                users[base64_decode(username)] = {
                    "password": base64_decode(password),
                    "realIP": real_ip,
                    "subIP": sub_ip,
                    "userID": user_id
                }
                client_sub_ips[username] = sub_ip
                traffic_logs[user_id] = []  # Initialize traffic log for the user
    print("[OK] Users loaded successfully.")

def load_domains_from_file():
    if not os.path.exists("domains.txt"):
        print("[INFO] No domains file found, starting fresh.")
        return

    with open("domains.txt", "r") as file:
        for line in file:
            parts = line.strip().split(",")
            if len(parts) >= 2:  # Ensure at least domain and ownerUserID are present
                encoded_domain = parts[0]
                owner_user_id = parts[1]
                redirect = parts[2] if len(parts) > 2 and parts[2] else None
                domains[encoded_domain] = {
                    "ownerUserID": owner_user_id,
                    "redirect": redirect
                }
    print("[OK] Domains loaded successfully.")

# Save a user to file
def save_user_to_file(username, password, real_ip, sub_ip, user_id):
    with open("users.txt", "a") as file:
        file.write(f"{username},{password},{real_ip},{sub_ip},{user_id}\n")

# Generate a new Sub-IP
def generate_sub_ip(file_path="users.txt"):
    with lock:
        # Read the Sub-IP prefix from the configuration
        sub_ip_prefix = config.get("subIPPrefix", "192.0.").strip()
        print(f"Raw Sub-IP Prefix from config: '{sub_ip_prefix}'")

        # Ensure the prefix ends with a dot (e.g., "192.0.0.")
        if not sub_ip_prefix.endswith("."):
            sub_ip_prefix += "."

        # Validate the Sub-IP prefix
        prefix_octets = sub_ip_prefix[:-1].split(".")  # Remove the trailing dot before splitting
        print(f"Prefix Octets: {prefix_octets}, Length: {len(prefix_octets)}")

        if len(prefix_octets) != 2 or not all(o.isdigit() and 0 <= int(o) < 256 for o in prefix_octets):
            raise ValueError(
                f"Invalid Sub-IP prefix in config: {sub_ip_prefix}. "
                f"Expected format: 'X.Y.Z.' (e.g., '192.168.1.')"
            )

        existing_ips = set()
        try:
            with open(file_path, "r") as file:
                for line in file:
                    parts = line.strip().split(",")
                    if len(parts) >= 4:  # Ensure there is a Sub-IP field
                        sub_ip = parts[3]
                        if sub_ip.startswith(sub_ip_prefix):
                            octets = list(map(int, sub_ip.split(".")))
                            ip_as_int = (octets[2] * 256) + octets[3]
                            existing_ips.add(ip_as_int)
        except FileNotFoundError:
            print(f"[INFO] File '{file_path}' not found. Starting fresh.")

        # Find the next available Sub-IP
        next_ip = 1  # Starting with the fourth octet
        while next_ip in existing_ips:
            next_ip += 1

        # Convert the integer into octets
        octet3 = (next_ip // 256) % 256
        octet4 = next_ip % 256

        # Ensure we don't exceed the valid range
        if octet3 > 255:
            raise ValueError("IP address range exhausted!")

        # Return the new Sub-IP
        return f"{sub_ip_prefix}{octet3}.{octet4}"


# Get Sub-IP for a given User ID
def get_sub_ip_for_user_id(user_id):
    for username, data in users.items():
        if data["userID"] == user_id:
            return data["subIP"]
    return None

def count_domains_for_user(user_id):
    return sum(1 for data in domains.values() if data["owner"] == user_id)
def save_domains_to_file():
    try:
        with open("domains.txt", "w") as file:
            for domain, details in domains.items():
                file.write(f"{domain},{details['ownerUserID']}\n")
        print("[DEBUG] Domains saved successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to save domains: {str(e)}")

@app.route("/isp/update_subip", methods=["POST"])
def update_subip():
    try:
        data = request.json
        isp_id = data.get("ispID")
        new_subip_prefix = data.get("subIPPrefix")

        if not isp_id or not new_subip_prefix:
            return jsonify({"error": "Missing ispID or subIPPrefix"}), 400

        # Validate the new Sub-IP prefix
        prefix_octets = new_subip_prefix[:-1].split(".") if new_subip_prefix.endswith(".") else new_subip_prefix.split(".")
        if len(prefix_octets) != 3 or not all(o.isdigit() and 0 <= int(o) < 256 for o in prefix_octets):
            return jsonify({"error": f"Invalid Sub-IP Prefix format: {new_subip_prefix}. Expected 'X.Y.Z.'"}), 400

        # Check for conflicts with other known ISPs
        for known_isp_id, isp_details in isps.items():
            if known_isp_id != isp_id and isp_details["subIPPrefix"] == new_subip_prefix:
                # Conflict detected
                print(f"[WARNING] Conflict: ISP {isp_id} trying to set conflicting Sub-IP Prefix {new_subip_prefix}.")
                return jsonify({
                    "error": "Sub-IP Prefix conflict detected. Please choose a different prefix."
                }), 409

        # Update the requesting ISP's Sub-IP prefix if no conflict
        if isp_id in isps:
            isps[isp_id]["subIPPrefix"] = new_subip_prefix
            save_isps_to_file()
            print(f"[INFO] Updated Sub-IP Prefix for ISP {isp_id} to {new_subip_prefix}.")
            return jsonify({"message": "Sub-IP Prefix updated successfully."}), 200
        else:
            return jsonify({"error": "ISP not found."}), 404

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

#SAS, switched access services
@app.route("/sas", methods=["POST"])
def sas():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        # Authenticate admin credentials
        if username != config.get("adminUsername") or password != config.get("adminPassword"):
           return jsonify({"error": "Unauthorized"}), 403
        action = data.get("action")

        # WHOIS Command
        if action == "whois":
            print(f"Data: {data}")
            target = data.get("user") or data.get("subIP") or data.get("ispID")
            if target in users:
                user = users.get(target)
                return jsonify({
                    "username": target,
                    "userID": user["userID"],
                    "subIP": user["subIP"],
                    "realIP": user["realIP"],
                    "lastKnownIP": user.get("lastKnownIP", "Unknown"),
                    "domains": [
                        base64_decode(domain) for domain, details in domains.items()
                        if details["ownerUserID"] == user["userID"]
                    ]   
                }), 200
            elif target in isps:
                isp = isps.get(target)
                return jsonify({
                    "ispID": target,
                    "subIPPrefix": isp["subIPPrefix"],
                    "realIP": isp["realIP"],
                    "port": isp["port"],
                    "domains": isp["domains"]
                }), 200
            for isp_id, isp in isps.items():
                if target.startswith(isp["subIPPrefix"]):
                    try:
                        response = requests.post(
                            f"http://{isp['realIP']}:{isp['port']}/isp/whois",
                            json={
                                "subIP": target
                            }
                        )
                        if response.status_code == 200:
                            return response.json(), 200
                        elif response.status_code == 404:
                            return jsonify({"error": "Target not found on remote ISP"}), 404
                        else:
                            return jsonify({"error": "Failed to retrieve information from remote ISP"}), 502
                    except Exception as e:
                        return jsonify({"error": "Failed to forward request to remote ISP"}), 502
            else:
                return jsonify({"error": "Target not found"}), 404

        # Blacklist ISP by IP Command
        elif action == "ISPblacklist":
            target_ip = data.get("realIP")
            if not target_ip:
                return jsonify({"error": "Missing realIP"}), 400

            # Find ISP by realIP
            isp_to_blacklist = next((isp_id for isp_id, isp in isps.items() if isp["realIP"] == target_ip), None)

            if not isp_to_blacklist:
                return jsonify({"error": "ISP with specified IP not found"}), 404

            # Blacklist the ISP
            isps[isp_to_blacklist]["blacklisted"] = True
            save_isps_to_file()
            return jsonify({"message": f"ISP with IP {target_ip} blacklisted successfully"}), 200
        elif action == "listISPs":
            return jsonify({
                "knownISPs": isps,
                "unknownISPs": unknown_isps
            }), 200

        # Accept ISP Request
        elif action == "acceptRequest":
            isp_id = data.get("ispID")
            if not isp_id or isp_id not in unknown_isps:
                return jsonify({"error": "Invalid or missing ISP ID"}), 400

            # Move ISP from unknown to known
            isp_details = unknown_isps.pop(isp_id)
            isp_details["lastSeen"] = datetime.utcnow()
            isp_details["token"] = uuid.uuid4().hex  # Generate a secure token
            isps[isp_id] = isp_details

            save_isps_to_file()
            save_unknown_isps_to_file()

            print(f"[INFO] ISP {isp_id} accepted and added to known ISPs.")
            return jsonify({"message": f"ISP {isp_id} accepted and added to known ISPs"}), 200

        # Deny ISP Request
        elif action == "denyRequest":
            isp_id = data.get("ispID")
            if not isp_id or isp_id not in unknown_isps:
                return jsonify({"error": "Invalid or missing ISP ID"}), 400

            # Remove ISP from unknown list
            unknown_isps.pop(isp_id, None)
            save_unknown_isps_to_file()

            print(f"[INFO] ISP {isp_id} denied and removed from review list.")
            return jsonify({"message": f"ISP {isp_id} denied and removed from review list"}), 200

        # Ping Command
        elif action == "ping":
            target_sub_ip = data.get("subIP")
            if not target_sub_ip:
                return jsonify({"error": "Missing Sub-IP"}), 400

            # Check if the target Sub-IP belongs to a local user
            user = next((u for u in users.values() if u["subIP"] == target_sub_ip), None)

            if user and user.get("realIP"):
                # Perform ping on local user's real IP
                real_ip = user["realIP"]
                platform = sys.platform

                if platform.startswith("win"):  # Windows
                    ping_command = ["ping", "-n", "1", real_ip]
                else:  # Linux/Unix
                    ping_command = ["ping", "-c", "1", real_ip]

                try:
                    import subprocess
                    result = subprocess.run(ping_command, capture_output=True, text=True)

                    if result.returncode == 0:
                        output = result.stdout
                        if platform.startswith("win"):
                            latency = next((line for line in output.splitlines() if "time=" in line), None)
                            latency = latency.split("time=")[-1].split("ms")[0].strip() if latency else "N/A"
                        else:
                            latency = result.stdout.split("time=")[-1].split(" ms")[0]

                        return jsonify({"message": "Ping successful", "latency_ms": latency}), 200
                    else:
                        return jsonify({"error": "Ping failed"}), 500
                except Exception as e:
                    return jsonify({"error": "Internal Server Error"}), 500

            # If not local, forward to the appropriate ISP
            for isp_id, isp in isps.items():
                if target_sub_ip.startswith(isp["subIPPrefix"]):  # Check if Sub-IP matches ISP's prefix
                    try:
                        # Forward the ping request to the remote ISP
                        response = requests.post(
                            f"http://{isp['realIP']}:{isp['port']}/isp/ping",
                            json={"subIP": target_sub_ip}
                        )

                        # Return the response from the remote ISP
                        if response.status_code == 200:
                            return response.json(), 200
                        else:
                            return jsonify({"error": "Remote ISP ping failed", "details": response.json()}), response.status_code
                    except Exception as e:
                        return jsonify({"error": "Failed to contact remote ISP"}), 502

            # If Sub-IP is not found locally or with any ISP
            return jsonify({"error": "Target Sub-IP not found"}), 404

        # View Logs Command
        elif action == "viewLogs":
            log_type = data.get("type", "traffic")
            if log_type == "traffic":
                return jsonify({"logs": traffic_logs}), 200
            else:
                return jsonify({"error": "Log type not supported"}), 400

        # Bulk Delete Domains by User
        elif action == "BulkDeleteDomainByUser":
            target_user_id = data.get("userID")
            if not target_user_id:
                return jsonify({"error": "Missing userID"}), 400

            # Find the target user
            target_user = next((user for user in users.values() if user["userID"] == target_user_id), None)
            if not target_user:
                return jsonify({"error": "User not found"}), 404

            # Filter and delete domains owned by the user
            domains_to_delete = [
                domain for domain, details in domains.items()
                if details["ownerUserID"] == target_user_id
            ]

            for domain in domains_to_delete:
                del domains[domain]

            # Save updated domains to file
            save_domains_to_file()

            return jsonify({
                "message": f"Deleted {len(domains_to_delete)} domains for user {target_user_id}.",
                "deletedDomains": [base64_decode(domain) for domain in domains_to_delete]
            }), 200

        elif action == "listUsers":
            user_list = [
                {
                    "username": username,
                    "userID": details["userID"],
                    "subIP": details["subIP"],
                    "realIP": details["realIP"],
                    "lastKnownIP": details.get("lastKnownIP", "Unknown"),
                }
                for username, details in users.items()
            ]
            return jsonify({"users": user_list}), 200
        # Invalid Action
        else:
            return jsonify({"error": "Invalid action"}), 400

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/domain/register", methods=["POST"])
def register_domain():
    try:
        # Parse incoming JSON
        data = request.json
        print(f"[DEBUG] Register domain data: {data}")

        # Validate 'fromUserID'
        from_user_id = data.get("ownerUserID")
        if not from_user_id:
            return jsonify({"error": "Missing ownerUserID"}), 400

        # Find the username for the provided user ID
        username = None
        for user, details in users.items():
            if details["userID"] == from_user_id:
                username = user
                break

        if not username:
            return jsonify({"error": "Invalid ownerUserID"}), 400

        # Decode and validate 'domain'
        domain = base64_decode(data.get("domain", ""))
        if not domain:
            return jsonify({"error": "Missing or invalid domain"}), 400

        # Base64 encode the domain for server-side storage
        encoded_domain = base64_encode(domain)

        # Check if the domain is already registered
        if encoded_domain in domains:
            return jsonify({"error": "Domain already registered"}), 409

        # Check if the user has exceeded their domain limit
        user_domains = [
            dom for dom, details in domains.items() if details["ownerUserID"] == from_user_id
        ]
        print(f"[DEBUG] User has {len(user_domains)} domains.")
        if len(user_domains) >= 5:
            return jsonify({"error": "Domain limit exceeded"}), 400

        # Register the domain
        domains[encoded_domain] = {"ownerUserID": from_user_id}
        save_domains_to_file()

        # Notify other ISPs about the new domain
        notify_isps_about_domain(encoded_domain, from_user_id)

        return jsonify({"message": "Domain registered successfully."}), 200

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

def notify_isps_about_domain(encoded_domain, owner_user_id):
    for isp_id, isp in isps.items():
        try:
            response = requests.post(
                f"http://{isp['realIP']}:{isp['port']}/domain/sync",
                json={"domain": encoded_domain, "ownerUserID": owner_user_id}
            )
        except Exception as e:
            print(f"[ERROR] Failed to notify ISP {isp_id}: {str(e)}")

@app.route("/domain/sync", methods=["POST"])
def sync_domain():
    try:
        data = request.json
        encoded_domain = data.get("domain")
        owner_user_id = data.get("ownerUserID")

        if not encoded_domain or not owner_user_id:
            return jsonify({"error": "Missing domain or ownerUserID"}), 400

        # Update or register the domain locally
        domains[encoded_domain] = {"ownerUserID": owner_user_id}
        save_domains_to_file()

        return jsonify({"message": "Domain synchronized successfully."}), 200

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

def request_domains_from_isps():
    """Request domain files from all known ISPs and check for conflicts."""
    for isp_id, isp in isps.items():
        try:
            response = requests.get(f"http://{isp['realIP']}:{isp['port']}/domain/export")
            if response.status_code == 200:
                remote_domains = response.json().get("domains", {})
                check_domain_conflicts(remote_domains, isp_id)
            else:
                print(f"[ERROR] Failed to fetch domains from ISP {isp_id}: {response.status_code}")
        except Exception as e:
            print(f"[ERROR] Exception while requesting domains from ISP {isp_id}: {str(e)}")

def check_domain_conflicts(remote_domains, isp_id):
    """Check for conflicts between local and remote domains."""
    conflicts = []
    for domain, details in remote_domains.items():
        if domain in domains:
            local_owner = domains[domain]["ownerUserID"]
            remote_owner = details["ownerUserID"]
            if local_owner != remote_owner:
                conflicts.append(domain)

    if conflicts:
        print(f"[WARNING] Domain conflicts detected with ISP {isp_id}: {conflicts}")

@app.route("/domain/export", methods=["GET"])
def export_domains():
    try:
        # Ensure the request comes from a known ISP
        real_ip = request.remote_addr
        known_isp = next((isp for isp in isps.values() if isp["realIP"] == real_ip), None)

        if not known_isp:
            return jsonify({"error": "Unauthorized access: IP not recognized as a known ISP"}), 403

        # Return the list of domains if the request is authorized
        return jsonify({"domains": domains}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500
 

@app.route("/domain/query", methods=["POST"])
def query_domain():
    try:
        data = request.json
        domain = data.get("domain")
        if not domain:
            return jsonify({"error": "Missing domain"}), 400
        real_ip = request.remote_addr  # Get the sender's IP address

        # Check locally first
        for encoded_domain, details in domains.items():
            if encoded_domain == domain:
                owner_user_id = details["ownerUserID"]

                # Find the owner's username based on the User ID
                owner_username = next(
                    (username for username, info in users.items() if info["userID"] == owner_user_id),
                    None
                )
                if not owner_username:
                    break

                # Return the username and redirect (if available)
                return jsonify({
                    "ownerUsername": owner_username,
                    "redirect": details.get("redirect")  # Include redirect if it exists
                }), 200

        # If not found locally, check with known ISPs
        for isp_id, isp in isps.items():
            # Skip the current ISP if the real IP matches the sender's IP
            if isp["realIP"] == real_ip:
                continue

            try:
                response = requests.post(
                    f"http://{isp['realIP']}:{isp['port']}/domain/query",
                    json={"domain": domain}
                )
                if response.status_code == 200:
                    return response.json(), 200
                elif response.status_code == 404:
                    continue  # If the ISP doesn't find it, try the next one
                else:
                    return jsonify({"error": "Error querying domain on ISP", "details": response.json()}), response.status_code
            except Exception as e:
                print(f"[ERROR] Exception querying ISP {isp_id} for domain {domain}: {str(e)}")
                continue  # Skip to the next ISP

        # If the domain is not found locally or on any ISP
        return jsonify({"error": "Domain not found"}), 404

    except Exception as e:
        print(f"[ERROR] Exception in /domain/query: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/domain/redirect", methods=["POST"])
def redirect_domain():
    try:
        data = request.json
        print(f"[DEBUG] Redirect domain data: {data}")

        # Validate the incoming data
        domain = data.get("domain")
        owner_user_id = data.get("ownerUserID")
        target = data.get("targetSubIP")

        if not domain or not owner_user_id or not target:
            return jsonify({"error": "Missing domain, ownerUserID, or target"}), 400

        # Base64 encode the domain for server-side comparison
        encoded_domain = base64_encode(base64_decode(domain))
        domain_details = domains.get(encoded_domain)

        if not domain_details:
            return jsonify({"error": "Domain not found"}), 404

        # Check if the provided ownerUserID matches the domain owner
        if domain_details["ownerUserID"] != owner_user_id:
            return jsonify({"error": "Forbidden: You do not own this domain"}), 403

        # Update the domain redirect
        domains[encoded_domain]["redirect"] = target
        save_domains_to_file()
        return jsonify({"message": "Domain redirected successfully"}), 200

    except Exception as e:
        print(f"[ERROR] Exception in /domain/redirect: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500



@app.route("/domain/transfer", methods=["POST"])
def transfer_domain():
    data = request.json
    domain = base64_decode(data.get("domain"))
    current_owner_user_id = data.get("currentOwnerUserID")
    new_owner_username = base64_decode(data.get("newOwnerUsername", ""))  # Decode the recipient username

    if not domain or not current_owner_user_id or not new_owner_username:
        return jsonify({"error": "Missing required fields"}), 400

    # Find the new owner's User ID based on the username
    new_owner_user = users.get(new_owner_username)
    if not new_owner_user:
        return jsonify({"error": "Recipient username not found"}), 404

    new_owner_user_id = new_owner_user["userID"]

    # Proceed with the transfer logic as before
    for encoded_domain, details in domains.items():
        if base64_decode(encoded_domain) == domain:
            if details["ownerUserID"] != current_owner_user_id:
                return jsonify({"error": "You do not own this domain"}), 403
            details["ownerUserID"] = new_owner_user_id
            save_domains_to_file()
            return jsonify({"message": f"Domain '{domain}' transferred to '{new_owner_username}'"}), 200

    return jsonify({"error": "Domain not found"}), 404


# Register endpoint
@app.route("/register", methods=["POST"])
def register():
    if request.content_type == "application/json":
        data = request.json
    else:
        body = request.data.decode("utf-8")
        data = dict(line.split("=") for line in body.split("\n") if "=" in line)

    username = data.get("username", "")
    password = data.get("password", "")
    real_ip = request.remote_addr

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    if username in users:
        return jsonify({"error": "Conflict: Username already exists"}), 409

    sub_ip = generate_sub_ip()
    user_id = str(uuid.uuid4())
    users[username] = {
        "password": password,
        "realIP": real_ip,
        "subIP": sub_ip,
        "userID": user_id
    }
    client_sub_ips[username] = sub_ip
    traffic_logs[user_id] = []  # Initialize traffic log for the user
    save_user_to_file(username, password, real_ip, sub_ip, user_id)
    return jsonify({
        "message": "Registration successful",
        "subIP": sub_ip,
        "userID": user_id
    })

# Login endpoint
@app.route("/login", methods=["POST"])
def login():
    if request.content_type == "application/json":
        data = request.json
    else:
        body = request.data.decode("utf-8")
        data = dict(line.split("=") for line in body.split("\n") if "=" in line)

    username = base64_decode(data.get("username", ""))
    password = base64_decode(data.get("password", ""))
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({
        "message": "Login successful",
        "subIP": user["subIP"],
        "userID": user["userID"]
    })

# Listen endpoint
@app.route("/listen", methods=["POST"])
def listen():
    try:
        if not request.json:
            return "Invalid or missing JSON payload", 400

        user_id = request.json.get("userID")
        if not user_id or user_id not in traffic_logs:
            return "Invalid userID", 400

        logs = traffic_logs[user_id]
        traffic_logs[user_id] = []  # Clear the log after sending
        return jsonify({"logs": logs})
    except Exception as e:
        print(f"[ERROR] {e}")
        return "Internal Server Error", 500

# Send endpoint
@app.route("/send", methods=["POST"])
def send_message():
    try:
        data = request.json
        target_sub_ip = data.get("targetSubIP")
        message = base64_decode(data.get("message", ""))

        if not target_sub_ip or not message:
            return jsonify({"error": "Missing required fields"}), 400

        # Determine if the source is local or remote
        real_ip = request.remote_addr
        is_local = any(user["realIP"] == real_ip for user in users.values())

        if is_local:
            from_user_id = data.get("fromUserID")
            from_sub_ip = get_sub_ip_for_user_id(from_user_id) if from_user_id else None
            if not from_sub_ip:
                return jsonify({"error": "Invalid fromUserID"}), 400
        else:
            from_sub_ip = data.get("fromSubIP")
            if not from_sub_ip:
                return jsonify({"error": "Missing fromSubIP for remote ISP"}), 400
        # Local delivery
        for user_id, sub_ip in [(u["userID"], u["subIP"]) for u in users.values()]:
            if sub_ip == target_sub_ip:
                traffic_logs[user_id].append({"from": from_sub_ip, "message": base64_encode(message)})
                return jsonify({"message": "Message sent successfully"}), 200
        # Remote delivery
        for isp_id, isp in isps.items():
            print(isp["subIPPrefix"])
            if target_sub_ip.startswith(isp["subIPPrefix"]):
                print("MATCH FOUND FOR ISP")
                response = requests.post(
                    f"http://{isp['realIP']}:{isp['port']}/send",
                    json={"fromSubIP": from_sub_ip, "targetSubIP": target_sub_ip, "message": base64_encode(message)}
                )
                return response.json(), response.status_code

        return jsonify({"error": "Target Sub-IP not found on network"}), 404

    except Exception as e:
        #print(f"[ERROR] Exception in /send: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


# Reverse Webserver Endpoint with GET Support
@app.route("/reverse", methods=["POST"])
def reverse_webserver():
    try:
        data = request.json

        # Extract necessary fields
        target_sub_ip = data.get("targetSubIP")
        method = data.get("method", "").upper()
        path = data.get("path", "")
        post_data = data.get("data", "")
        from_user_id = data.get("fromUserID")
        request_id = data.get("requestID") or str(uuid.uuid4())  # Generate requestID if not provided
        # Validate inputs
        if not target_sub_ip or not method or not path:
            return jsonify({"error": "Missing required fields"}), 400

        if method not in ["GET", "POST"]:
            return jsonify({"error": "Unsupported method"}), 400

        # Determine if the source is local or remote
        real_ip = request.remote_addr
        is_local = any(user["realIP"] == real_ip for user in users.values())

        from_sub_ip = None
        if is_local:
            # Local Request: Resolve sender's Sub-IP
            if not from_user_id:
                return jsonify({"error": "Missing fromUserID for local client"}), 400
            from_sub_ip = get_sub_ip_for_user_id(from_user_id)
            if not from_sub_ip:
                return jsonify({"error": "Invalid fromUserID"}), 400
        else:
            # Remote Request: Resolve sender's Sub-IP
            from_sub_ip = data.get("fromSubIP")
            if not from_sub_ip:
                return jsonify({"error": "Missing fromSubIP for remote ISP"}), 400

        # Check if the target Sub-IP is local
        for user_id, sub_ip in [(u["userID"], u["subIP"]) for u in users.values()]:
            if sub_ip == target_sub_ip:
                # Local Request Handling
                target_user_id = user_id

                # Create and append the reverse request message
                message = base64_encode(f"{method}:{path}|{post_data}" if method == "POST" else f"{method}:{path}")
                traffic_logs[target_user_id].append({
                    "from": from_sub_ip,
                    "message": message,
                    "requestID": request_id  # Add requestID for tracking
                })

                # Wait for response
                def wait_for_response():
                    for _ in range(45):  # Max 45 seconds
                        logs = traffic_logs[target_user_id]
                        for log in logs:
                            if log.get("from") == from_sub_ip and log.get("requestID") == request_id and "response" in log:
                                return log["response"]
                        time.sleep(0.1)
                    return None

                response = wait_for_response()
                if response:
                    return jsonify({"response": base64_encode(response), "requestID": request_id}), 200
                else:
                    return jsonify({"error": "Timeout waiting for response", "requestID": request_id}), 504

        # If not local, forward the request to the responsible ISP
        for isp_id, isp in isps.items():
            if target_sub_ip.startswith(isp["subIPPrefix"]):
                try:
                    response = requests.post(
                        f"http://{isp['realIP']}:{isp['port']}/reverse",
                        json={
                            "targetSubIP": target_sub_ip,
                            "method": method,
                            "path": path,
                            "data": post_data,
                            "fromSubIP": from_sub_ip,
                            "requestID": request_id
                        }
                    )
                    return response.json(), response.status_code
                except Exception as e:
                    return jsonify({"error": "Failed to forward request to remote ISP"}), 502

                # If no match is found, return an error
        return jsonify({"error": "Target Sub-IP not found"}), 404
    
    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

# Save ISPs to a file
def save_isps_to_file(file_path="isps.json"):
    try:
        # Pre-process data to make it JSON-serializable
        serializable_data = {
            isp_id: {
                **details,
                "lastSeen": details["lastSeen"].isoformat()  # Convert datetime to string
            }
            for isp_id, details in isps.items()
        }
        with open(file_path, "w") as file:
            json.dump(serializable_data, file, indent=4)  # Save as pretty-printed JSON
        print("[INFO] ISPs saved to file.")
    except Exception as e:
        print(f"[ERROR] Failed to save ISPs: {str(e)}")

# Load ISPs from a file
def load_isps_from_file(file_path="isps.json"):
    global isps
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as file:
                data = json.load(file)
                for isp_id, details in data.items():
                    details["lastSeen"] = datetime.fromisoformat(details["lastSeen"])
                isps.update(data)
            print("[INFO] ISPs loaded from file.")
        except Exception as e:
            print(f"[ERROR] Failed to load ISPs: {str(e)}")
    else:
        print("[INFO] No ISP data file found.")

@app.route("/isp/whois", methods=["POST"])
def isp_whois():
    try:
        # Ensure the request comes from a known ISP
        real_ip = request.remote_addr
        known_isp = next((isp for isp in isps.values() if isp["realIP"] == real_ip), None)

        if not known_isp:
            return jsonify({"error": "Unauthorized"}), 403

        # Extract the Sub-IP parameter
        data = request.json
        target_sub_ip = data.get("subIP")
        if not target_sub_ip:
            return jsonify({"error": "Missing Sub-IP"}), 400

        # Check if the Sub-IP belongs to a local user
        user_entry = next(((username, u) for username, u in users.items() if u["subIP"] == target_sub_ip), None)
        if user_entry:
            username, user = user_entry
    # Exclude `userID` for remote queries
            response_data = {
                "username": username,
                "subIP": user["subIP"],
                "realIP": user["realIP"],
                "lastKnownIP": user.get("lastKnownIP", "Unknown"),
                "domains": [
                    base64_decode(domain) for domain, details in domains.items()
                    if details["ownerUserID"] == user["userID"]
                ]
            }
            return jsonify(response_data), 200

        # If Sub-IP belongs to an ISP
        isp = next((isp for isp in isps.values() if target_sub_ip.startswith(isp["subIPPrefix"])), None)
        if isp:
            return jsonify({
                "ispID": isp["ispID"],
                "subIPPrefix": isp["subIPPrefix"],
                "realIP": isp["realIP"],
                "port": isp["port"],
                "domains": isp["domains"]
            }), 200

        # If no match is found locally
        return jsonify({"error": "Target not found"}), 404

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500


@app.route("/isp/ping", methods=["POST"])
def isp_ping():
    try:
        # Ensure the request comes from a known ISP
        real_ip = request.remote_addr
        known_isp = next((isp for isp in isps.values() if isp["realIP"] == real_ip), None)

        if not known_isp:
            return jsonify({"error": "Unauthorized"}), 403

        # Extract target Sub-IP
        data = request.json
        target_sub_ip = data.get("subIP")
        if not target_sub_ip:
            return jsonify({"error": "Missing Sub-IP"}), 400

        # Check if the Sub-IP belongs to a user
        user = next((u for u in users.values() if u["subIP"] == target_sub_ip), None)
        if not user or not user.get("realIP"):
            return jsonify({"error": "User or Real IP not found"}), 404

        # Perform ping to the user's real IP
        real_ip = user["realIP"]
        platform = sys.platform

        ping_command = (
            ["ping", "-n", "1", real_ip] if platform.startswith("win")
            else ["ping", "-c", "1", real_ip]
        )

        start_time = time.time()  # Start timing
        try:
            import subprocess
            result = subprocess.run(ping_command, capture_output=True, text=True)
            end_time = time.time()  # End timing

            if result.returncode == 0:
                latency_ms = int((end_time - start_time) * 1000)  # Convert to ms
                return jsonify({
                    "message": f"Responded in {latency_ms} ms",
                    "latency_ms": latency_ms
                }), 200
            else:
                return jsonify({"error": "Ping failed"}), 500
        except Exception as e:
            return jsonify({"error": "Internal Server Error"}), 500

    except Exception as e:
        print(f"[ERROR] Exception in /isp/ping: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

#ISP registeration endpoint
@app.route("/isp/register", methods=["POST"])
def register_isp():
    try:
        data = request.json
        isp_id = data.get("ispID") or str(uuid.uuid4())
        sub_ip_prefix = data.get("subIPPrefix")
        real_ip = data.get("realIP")
        port = data.get("port")
        real_networking = data.get("realNetworking", False)
        incoming_domains = data.get("domains", {})
        known_isps = data.get("knownISPs", {})

        if not sub_ip_prefix or not real_ip or not port:
            return jsonify({"error": "Missing required fields"}), 400

        # Check for domain conflicts
        conflicting_domains = [domain for domain in incoming_domains if domain in domains]
        if conflicting_domains:
            print(f"[INFO] Domain conflicts detected: {conflicting_domains}")
            return jsonify({
                "error": "Domain conflicts detected",
                "conflictingDomains": conflicting_domains
            }), 409

        # Check if the ISP is already registered
        if isp_id in isps:
            print(f"[INFO] Updating existing ISP {isp_id}.")
            isps[isp_id].update({
                "subIPPrefix": sub_ip_prefix,
                "realIP": real_ip,
                "port": port,
                "realNetworking": real_networking,
                "domains": incoming_domains,
                "lastSeen": datetime.utcnow()
            })
            save_isps_to_file()
            return jsonify({"message": "ISP updated successfully."}), 200

        # If the ISP is not registered, add to unknown ISPs for review
        unknown_isps[isp_id] = {
            "subIPPrefix": sub_ip_prefix,
            "realIP": real_ip,
            "port": port,
            "realNetworking": real_networking,
            "domains": incoming_domains,
            "lastSeen": datetime.utcnow()
        }
        save_unknown_isps_to_file()

        print(f"[INFO] ISP {isp_id} added to unknown ISPs for review.")
        return jsonify({
            "message": f"ISP {isp_id} added to review list."
        }), 202

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500


@app.route("/isp/acceptRequest", methods=["POST"])
def accept_request():
    try:
        data = request.json
        isp_id = data.get("ispID")
        if not isp_id or isp_id not in unknown_isps:
            return jsonify({"error": "Invalid or missing ISP ID"}), 400

        # Move from unknown to known ISPs
        isp_details = unknown_isps.pop(isp_id)
        isp_details["lastSeen"] = datetime.utcnow()
        isp_details["token"] = uuid.uuid4().hex  # Generate a secure token
        isps[isp_id] = isp_details

        save_isps_to_file()
        save_unknown_isps_to_file()

        print(f"[INFO] ISP {isp_id} accepted and added to known ISPs.")
        return jsonify({"message": f"ISP {isp_id} accepted and added to known ISPs"}), 200

    except Exception as e:
        print(f"[ERROR] Exception in /isp/acceptRequest: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


@app.route("/isp/denyRequest", methods=["POST"])
def deny_request():
    try:
        data = request.json
        isp_id = data.get("ispID")
        if not isp_id or isp_id not in unknown_isps:
            return jsonify({"error": "Invalid or missing ISP ID"}), 400

        # Remove from unknown ISPs
        unknown_isps.pop(isp_id, None)
        save_unknown_isps_to_file()

        print(f"[INFO] ISP {isp_id} denied and removed from review list.")
        return jsonify({"message": f"ISP {isp_id} denied and removed from review list"}), 200

    except Exception as e:
        print(f"[ERROR] Exception in /isp/denyRequest: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


def notify_isp_to_update_subip(isp_id):
    """Notify an ISP to manually update its Sub-IP prefix."""
    isp_details = isps.get(isp_id)
    if not isp_details:
        print(f"[ERROR] ISP {isp_id} not found for notification.")
        return

    try:
        response = requests.post(
            f"http://{isp_details['realIP']}:{isp_details['port']}/isp/update_subip",
            json={"message": "Please update your Sub-IP prefix due to conflict"}
        )
        if response.status_code == 200:
            print(f"[INFO] Notification sent to ISP {isp_id} to update Sub-IP prefix.")
        else:
            print(f"[ERROR] Failed to notify ISP {isp_id}: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Failed to notify ISP {isp_id}: {str(e)}")

def save_unknown_isps_to_file(file_path="unknown_isps.json"):
    """Save unknown ISPs to a file."""
    try:
        with open(file_path, "w") as file:
            json.dump(unknown_isps, file, indent=4)
        print("[INFO] Unknown ISPs saved to file.")
    except Exception as e:
        print(f"[ERROR] Failed to save unknown ISPs: {str(e)}")

def load_unknown_isps_from_file(file_path="unknown_isps.json"):
    """Load unknown ISPs from a file."""
    global unknown_isps
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as file:
                unknown_isps.update(json.load(file))
            print("[INFO] Unknown ISPs loaded from file.")
        except Exception as e:
            print(f"[ERROR] Failed to load unknown ISPs: {str(e)}")
    else:
        print("[INFO] No unknown ISPs file found.")


# Periodic configuration reloader
def reload_config_periodically():
    """
    Periodically reloads the configuration and applies changes.
    """
    while True:
        try:
            load_config()
            # Check for critical changes and avoid looping unnecessarily
            time.sleep(config.get("check_config_interval_seconds", 60))
        except Exception as e:
            print(f"[ERROR] Exception in configuration reloader: {str(e)}")
            time.sleep(60)  # Wait before retrying to avoid excessive logs


# Start the server
if __name__ == "__main__":
    load_config()
    load_users_from_file()
    load_domains_from_file()
    load_isps_from_file()
    load_unknown_isps_from_file()

    threading.Thread(target=request_domains_from_isps, daemon=True).start()
    threading.Thread(target=reload_config_periodically, daemon=True).start()
    app.run(host=config["host"], port=config["port"], threaded=True, debug=False)
