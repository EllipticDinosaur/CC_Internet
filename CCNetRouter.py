from flask import Flask, request, jsonify
import threading
import uuid
import os
import time
import base64

app = Flask(__name__)

# In-memory data structures
users = {}
traffic_logs = {}
domains = {}
client_sub_ips = {}
lock = threading.Lock()

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
        # Read existing Sub-IPs from the file
        existing_ips = set()
        try:
            with open(file_path, "r") as file:
                for line in file:
                    parts = line.strip().split(",")
                    if len(parts) >= 4:  # Ensure there is a Sub-IP field
                        sub_ip = parts[3]
                        if sub_ip.startswith("192."):
                            octets = list(map(int, sub_ip.split(".")))
                            ip_as_int = (octets[1] * 256**2) + (octets[2] * 256) + octets[3]
                            existing_ips.add(ip_as_int)
        except FileNotFoundError:
            print(f"[INFO] File '{file_path}' not found. Starting fresh.")

        # Find the next available Sub-IP
        next_ip = 1  # Starting at 192.0.0.1
        while next_ip in existing_ips:
            next_ip += 1

        # Convert the integer back into octets
        octet2 = (next_ip // 256**2) % 256
        octet3 = (next_ip // 256) % 256
        octet4 = next_ip % 256

        # Ensure we don't exceed the valid range
        if octet2 > 255:
            raise ValueError("IP address range exhausted!")
        
        # Return the new Sub-IP
        return f"192.{octet2}.{octet3}.{octet4}"
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

@app.route("/domain/register", methods=["POST"])
def register_domain():
    try:
        # Parse incoming JSON
        data = request.json
        print(f"[DEBUG] Register domain data: {data}")

        # Validate 'fromUserID'
        from_user_id = data.get("ownerUserID")
        if not from_user_id:
            print("[ERROR] Missing ownerUserID")
            return jsonify({"error": "Missing ownerUserID"}), 400

        # Find the username for the provided user ID
        username = None
        for user, details in users.items():
            if details["userID"] == from_user_id:
                username = user
                break

        if not username:
            print("[ERROR] Invalid ownerUserID")
            return jsonify({"error": "Invalid ownerUserID"}), 400

        # Decode and validate 'domain'
        domain = base64_decode(data.get("domain", ""))
        if not domain:
            print("[ERROR] Missing or invalid domain")
            return jsonify({"error": "Missing or invalid domain"}), 400

        # Base64 encode the domain for server-side storage
        encoded_domain = base64_encode(domain)

        # Check if the domain is already registered
        if encoded_domain in domains:
            print("[ERROR] Domain already registered")
            return jsonify({"error": "Domain already registered"}), 409

        # Check if the user has exceeded their domain limit
        user_domains = [
            dom for dom, details in domains.items() if details["ownerUserID"] == from_user_id
        ]
        print(f"[DEBUG] User has {len(user_domains)} domains.")
        if len(user_domains) >= 5:
            print("[ERROR] Domain limit exceeded")
            return jsonify({"error": "Domain limit exceeded"}), 400

        # Register the domain
        domains[encoded_domain] = {"ownerUserID": from_user_id}
        save_domains_to_file()
        print("[DEBUG] Domain registered successfully:", domain)
        return jsonify({"message": "Domain registered successfully."}), 200

    except Exception as e:
        print(f"[ERROR] Exception in /domain/register: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/domain/query", methods=["POST"])
def query_domain():
    try:
        data = request.json
        domain = data.get("domain")

        if not domain:
            return jsonify({"error": "Missing domain"}), 400

        # Search for the domain in the dictionary
        for encoded_domain, details in domains.items():
            if encoded_domain == domain:
                ownerUserID = details["ownerUserID"]
                # Find the owner's username based on the User ID
                owner_username = next((username for username, info in users.items() if info["userID"] == ownerUserID), None)

                if not owner_username:
                    return jsonify({"error": "Owner not found"}), 404

                # Return the domain details (excluding sensitive ownerUserID)
                return jsonify({
                    "ownerUsername": owner_username,  # Return the owner's username
                    "redirect": details.get("redirect")  # Include redirect if it exists
                }), 200

        # If the domain is not found, return an error
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
            print(f"[ERROR] Unauthorized access: {owner_user_id} does not own {domain}")
            return jsonify({"error": "Forbidden: You do not own this domain"}), 403

        # Update the domain redirect
        domains[encoded_domain]["redirect"] = target
        save_domains_to_file()
        print(f"[INFO] Domain '{domain}' redirected to '{target}' by owner '{owner_user_id}'")
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
    print(username)
    print(password)
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
        if request.content_type == "application/json":
            data = request.json
        else:
            data = request.form.to_dict()

        from_user_id = data.get("fromUserID")
        target_sub_ip = data.get("targetSubIP")
        message = base64_decode(data.get("message", ""))

        if not from_user_id or not target_sub_ip or not message:
            print("Missing required fields")
            return jsonify({"error": "Missing fromUserID, targetSubIP, or message"}), 400

        from_sub_ip = get_sub_ip_for_user_id(from_user_id)
        if not from_sub_ip:
            return jsonify({"error": "Invalid fromUserID"}), 400

        target_user_id = None
        for user_id, sub_ip in [(u["userID"], u["subIP"]) for u in users.values()]:
            if sub_ip == target_sub_ip:
                target_user_id = user_id
                break

        if not target_user_id:
            print("SUBIP NOT FOUND")
            return jsonify({"error": "Target Sub-IP not found"}), 404

        # Append the message to the target user's traffic log
        traffic_logs[target_user_id].append({
            "from": from_sub_ip,
            "message": base64_encode(message)
        })

        # Return success response
        return jsonify({"message": "Message sent successfully"}), 200

    except Exception as e:
        print(f"[ERROR] Exception in /send: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

# Reverse Webserver Endpoint with GET Support
@app.route("/reverse", methods=["POST"])
def reverse_webserver():
    try:
        data = request.json
        target_sub_ip = data.get("targetSubIP")
        method = data.get("method")
        path = data.get("path", "")
        post_data = data.get("data", "")

        if not target_sub_ip or not method or not path:
            return jsonify({"error": "Missing required fields"}), 400

        target_user_id = None
        for user_id, sub_ip in [(u["userID"], u["subIP"]) for u in users.values()]:
            if sub_ip == target_sub_ip:
                target_user_id = user_id
                break

        if not target_user_id:
            return jsonify({"error": "Target Sub-IP not found"}), 404

        from_user_id = data.get("fromUserID")  # Get the sender's user ID
        from_sub_ip = get_sub_ip_for_user_id(from_user_id)  # Get the sender's sub-IP
        if not from_sub_ip:
            return jsonify({"error": "Invalid sender information"}), 400

        if method.upper() == "GET":
            message = base64_encode(f"GET:{path}")
        elif method.upper() == "POST":
            message = base64_encode(f"POST:{path}|{post_data}")
        else:
            return jsonify({"error": "Unsupported method"}), 400

        # Append the sender's sub-IP (from_sub_ip) as the 'from' field
        traffic_logs[target_user_id].append({
            "from": from_sub_ip,  # Use the sender's sub-IP here
            "message": message
        })

        def wait_for_response():
            for _ in range(45):  # Max 45 seconds
                logs = traffic_logs[target_user_id]
                for log in logs:
                    if log.get("from") == target_sub_ip and log.get("response"):
                        return log["response"]
                time.sleep(0.1)
            return None

        response = wait_for_response()
        if response:
            return jsonify({"response": base64_encode(response)})
        else:
            return jsonify({"error": "Timeout"}), 504
    except Exception as e:
        print(f"[ERROR] Exception in /reverse: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

# Start the server
if __name__ == "__main__":
    load_users_from_file()
    load_domains_from_file()
    app.run(host="0.0.0.0", port=7080, threaded=True)
