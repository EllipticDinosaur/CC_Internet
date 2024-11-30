# API Documentation

## API Documentation

Comprehensive documentation for managing users, domains, ISPs, and messaging.

### Register User

Registers a new user in the system.

**Endpoint:** `POST /register`

**Parameters:**

- username: The username for the new user.

- password: The password for the new user.

**Response:**

```json
{
    "message": "Registration successful",
    "subIP": "192.0.0.1",
    "userID": "f1b44e74-5d8e-41c4-a6f9-1e674eb6c9e0"
}
```

**Examples:**

```curl -X POST http://example.com/register \
-H "Content-Type: application/json" \
-d '{"username": "john_doe", "password": "securepassword"}'
```

```http.post(
    "http://example.com/register",
    textutils.serializeJSON({ username = "john_doe", password = "securepassword" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"username": "john_doe", "password": "securepassword"}]]
local request = internet.request("http://example.com/register", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Login

Logs in a user and retrieves their user details.

**Endpoint:** `POST /login`

**Parameters:**

- username: The username of the user.

- password: The user's password.

**Response:**

```json
{
    "message": "Login successful",
    "subIP": "192.0.0.1",
    "userID": "f1b44e74-5d8e-41c4-a6f9-1e674eb6c9e0"
}
```

**Examples:**

```curl -X POST http://example.com/login \
-H "Content-Type: application/json" \
-d '{"username": "john_doe", "password": "securepassword"}'
```

```http.post(
    "http://example.com/login",
    textutils.serializeJSON({ username = "john_doe", password = "securepassword" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"username": "john_doe", "password": "securepassword"}]]
local request = internet.request("http://example.com/login", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Register Domain

Registers a new domain for a user.

**Endpoint:** `POST /domain/register`

**Parameters:**

- ownerUserID (string): The user ID of the domain owner.

- domain (string, Base64 required): The domain name to register.

**Response:**

```json
{
    "message": "Domain registered successfully."
}
```

**Examples:**

```curl -X POST http://example.com/domain/register \
-H "Content-Type: application/json" \
-d '{"ownerUserID": "12345", "domain": "ZG9tYWluLmNvbQ=="}'
```

```http.post(
    "http://example.com/domain/register",
    textutils.serializeJSON({ ownerUserID = "12345", domain = "ZG9tYWluLmNvbQ==" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"ownerUserID": "12345", "domain": "ZG9tYWluLmNvbQ=="}]]
local request = internet.request("http://example.com/domain/register", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Query Domain

Retrieve information about a registered domain.

**Endpoint:** `POST /domain/query`

**Parameters:**

- domain (string, Base64 required): The domain name to query.

**Response:**

```json
{
    "ownerUsername": "john_doe",
    "redirect": "192.0.0.2"
}
```

**Examples:**

```curl -X POST http://example.com/domain/query \
-H "Content-Type: application/json" \
-d '{"domain": "ZG9tYWluLmNvbQ=="}'
```

```http.post(
    "http://example.com/domain/query",
    textutils.serializeJSON({ domain = "ZG9tYWluLmNvbQ==" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"domain": "ZG9tYWluLmNvbQ=="}]]
local request = internet.request("http://example.com/domain/query", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Export Domains

Exports all domains registered locally.

**Endpoint:** `GET /domain/export`

**Response:**

```json
{
    "domains": {
        "ZG9tYWluLmNvbQ==": {
            "ownerUserID": "f1b44e74-5d8e-41c4-a6f9-1e674eb6c9e0",
            "redirect": null
        }
    }
}
```

**Examples:**

```curl -X GET http://example.com/domain/export
```

```local response = http.get("http://example.com/domain/export")
if response then
    print(response.readAll())
end
```

```local internet = require("internet")
local request = internet.request("http://example.com/domain/export")
for chunk in request do
    print(chunk)
end
```

### Register ISP

Registers a new ISP in the system.

**Endpoint:** `POST /isp/register`

**Parameters:**

- ispID (string): Optional unique identifier for the ISP.

- subIPPrefix (string): The Sub-IP prefix managed by the ISP.

- realIP (string): The real IP address of the ISP server.

- port (integer): The port the ISP server listens on.

- domains (object): Domains managed by the ISP.

- knownISPs (object): Other ISPs known to the registering ISP.

**Response:**

```json
{
    "message": "ISP registered successfully",
    "ispID": "1234-5678-isp"
}
```

**Examples:**

```curl -X POST http://example.com/isp/register \
-H "Content-Type: application/json" \
-d '{
    "subIPPrefix": "192.",
    "realIP": "203.0.113.10",
    "port": 8080,
    "domains": {},
    "knownISPs": {}
}'
```

```http.post(
    "http://example.com/isp/register",
    textutils.serializeJSON({ 
        subIPPrefix = "192.", 
        realIP = "203.0.113.10", 
        port = 8080, 
        domains = {}, 
        knownISPs = {} 
    }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{
    "subIPPrefix": "192.",
    "realIP": "203.0.113.10",
    "port": 8080,
    "domains": {},
    "knownISPs": {}
}]]
local request = internet.request("http://example.com/isp/register", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### ISP WHOIS

Retrieves information about a Sub-IP or ISP.

**Endpoint:** `POST /isp/whois`

**Parameters:**

- subIP (string): The target Sub-IP address to look up.

**Response:**

```json
{
    "username": "john_doe",
    "subIP": "192.0.0.2",
    "realIP": "203.0.113.15",
    "lastKnownIP": "Unknown",
    "domains": ["example.com", "anotherdomain.com"]
}
```

**Examples:**

```curl -X POST http://example.com/isp/whois \
-H "Content-Type: application/json" \
-d '{"subIP": "192.0.0.2"}'
```

```http.post(
    "http://example.com/isp/whois",
    textutils.serializeJSON({ subIP = "192.0.0.2" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"subIP": "192.0.0.2"}]]
local request = internet.request("http://example.com/isp/whois", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### ISP Ping

Pings a Sub-IP address to measure response time.

**Endpoint:** `POST /isp/ping`

**Parameters:**

- subIP (string): The Sub-IP address to ping.

**Response:**

```json
{
    "message": "Responded in 42 ms",
    "latency_ms": 42
}
```

**Examples:**

```curl -X POST http://example.com/isp/ping \
-H "Content-Type: application/json" \
-d '{"subIP": "192.0.0.2"}'
```

```http.post(
    "http://example.com/isp/ping",
    textutils.serializeJSON({ subIP = "192.0.0.2" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"subIP": "192.0.0.2"}]]
local request = internet.request("http://example.com/isp/ping", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### ISP Update SubIP

Updates the Sub-IP prefix for a known ISP.

**Endpoint:** `POST /isp/update_subip`

**Parameters:**

- ispID (string): The unique ID of the ISP to update.

- subIPPrefix (string): The new Sub-IP prefix (e.g., "192.0.1.").

**Response:**

```json
{
    "message": "Sub-IP Prefix updated successfully."
}
```

**Examples:**

```curl -X POST http://example.com/isp/update_subip \
-H "Content-Type: application/json" \
-d '{"ispID": "abc123", "subIPPrefix": "192.0.1."}'
```

```http.post(
    "http://example.com/isp/update_subip",
    textutils.serializeJSON({ ispID = "abc123", subIPPrefix = "192.0.1." }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"ispID": "abc123", "subIPPrefix": "192.0.1."}]]
local request = internet.request("http://example.com/isp/update_subip", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Send Message

Sends a message to a target user or ISP.

**Endpoint:** `POST /send`

**Parameters:**

- fromUserID (string): The user ID of the sender.

- targetSubIP (string): The Sub-IP of the recipient.

- message (string, Base64 required): The message to send.

**Response:**

```json
{
    "message": "Message sent successfully."
}
```

**Examples:**

```curl -X POST http://example.com/send \
-H "Content-Type: application/json" \
-d '{
    "fromUserID": "12345",
    "targetSubIP": "192.0.0.2",
    "message": "SGVsbG8sIFdvcmxkIQ=="
}'
```

```http.post(
    "http://example.com/send",
    textutils.serializeJSON({ 
        fromUserID = "12345", 
        targetSubIP = "192.0.0.2", 
        message = "SGVsbG8sIFdvcmxkIQ==" 
    }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{
    "fromUserID": "12345",
    "targetSubIP": "192.0.0.2",
    "message": "SGVsbG8sIFdvcmxkIQ=="
}]]
local request = internet.request("http://example.com/send", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Reverse Request

Sends a reverse web request to a target user or ISP.

**Endpoint:** `POST /reverse`

**Parameters:**

- targetSubIP (string): The Sub-IP of the recipient.

- method (string): The HTTP method (GET or POST).

- path (string): The target path.

- data (string): Data for POST requests.

**Response:**

```json
{
    "response": "Base64 encoded response from recipient"
}
```

**Examples:**

```curl -X POST http://example.com/reverse \
-H "Content-Type: application/json" \
-d '{
    "targetSubIP": "192.0.0.2",
    "method": "GET",
    "path": "/status"
}'
```

```http.post(
    "http://example.com/reverse",
    textutils.serializeJSON({ 
        targetSubIP = "192.0.0.2", 
        method = "GET", 
        path = "/status" 
    }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{
    "targetSubIP": "192.0.0.2",
    "method": "GET",
    "path": "/status"
}]]
local request = internet.request("http://example.com/reverse", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Register ISP


                Registers a new ISP in the system. If the ISP is already known, its details are updated.
                Otherwise, the ISP is added to the list of unknown ISPs for manual review.
            

**Endpoint:** `POST /isp/register`

**Parameters:**

- ispID (optional, string): A unique identifier for the ISP. Auto-generated if not provided.

- subIPPrefix (string): The Sub-IP prefix managed by the ISP.

- realIP (string): The real IP address of the ISP server.

- port (integer): The port the ISP server listens on.

- realNetworking (optional, boolean): Whether real networking is enabled for the ISP.

- domains (optional, object): Domains managed by the ISP.

- knownISPs (optional, object): Other ISPs known to the registering ISP.

**Response:**

```json
{
            "message": "ISP registered successfully",
            "ispID": "1234-5678-isp"
        }
```

**Examples:**

```curl -X POST http://example.com/isp/register \
        -H "Content-Type: application/json" \
        -d '{
            "subIPPrefix": "192.168.",
            "realIP": "203.0.113.10",
            "port": 8080,
            "realNetworking": true,
            "domains": {"example.com": "ownerID1"},
            "knownISPs": {"isp123": {"subIPPrefix": "192.169.", "realIP": "203.0.113.11", "port": 8081}}
        }'
```

```http.post(
            "http://example.com/isp/register",
            textutils.serializeJSON({ 
                subIPPrefix = "192.168.", 
                realIP = "203.0.113.10", 
                port = 8080, 
                realNetworking = true, 
                domains = {["example.com"] = "ownerID1"}, 
                knownISPs = {["isp123"] = {subIPPrefix = "192.169.", realIP = "203.0.113.11", port = 8081}}
            }),
            { ["Content-Type"] = "application/json" }
        )
```

```local internet = require("internet")
        local data = [[{
            "subIPPrefix": "192.168.",
            "realIP": "203.0.113.10",
            "port": 8080,
            "realNetworking": true,
            "domains": {"example.com": "ownerID1"},
            "knownISPs": {"isp123": {"subIPPrefix": "192.169.", "realIP": "203.0.113.11", "port": 8081}}
        }]]
        local request = internet.request("http://example.com/isp/register", data, { ["Content-Type"] = "application/json" })
        for chunk in request do
            print(chunk)
        end
```

### Accept ISP Request

Accepts a request from an unknown ISP and moves it to the known ISPs list.

**Endpoint:** `POST /isp/acceptRequest`

**Parameters:**

- ispID (string): The ID of the ISP to accept.

**Response:**

```json
{
    "message": "ISP {ispID} accepted and added to known ISPs"
}
```

**Examples:**

```curl -X POST http://example.com/isp/acceptRequest \
-H "Content-Type: application/json" \
-d '{"ispID": "12345"}'
```

```http.post(
    "http://example.com/isp/acceptRequest",
    textutils.serializeJSON({ ispID = "12345" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"ispID": "12345"}]]
local request = internet.request("http://example.com/isp/acceptRequest", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### Deny ISP Request

Denies a request from an unknown ISP and removes it from the review list.

**Endpoint:** `POST /isp/denyRequest`

**Parameters:**

- ispID (string): The ID of the ISP to deny.

**Response:**

```json
{
    "message": "ISP {ispID} denied and removed from review list"
}
```

**Examples:**

```curl -X POST http://example.com/isp/denyRequest \
-H "Content-Type: application/json" \
-d '{"ispID": "12345"}'
```

```http.post(
    "http://example.com/isp/denyRequest",
    textutils.serializeJSON({ ispID = "12345" }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{"ispID": "12345"}]]
local request = internet.request("http://example.com/isp/denyRequest", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

### SAS Command

Central endpoint for various SAS-related commands.

**Endpoint:** `POST /sas`

**Parameters:**

- action (string): The specific action to perform. Possible values include:

- whois: Look up user/ISP details.

- ISPblacklist: Blacklist an ISP by its real IP.

- listISPs: Lists all known and unknown ISPs.

- acceptRequest: Accepts an ISP request and moves it to the known ISPs list.

- denyRequest: Denies an ISP request and removes it from the unknown ISPs list.

- viewLogs: Views traffic logs for users.

- BulkDeleteDomainByUser: Deletes all domains associated with a specific user.

- listUsers: Lists all registered users.

- username (string): The admin username.

- password (string): The admin password.

- Additional parameters depend on the specific action selected.

**Response:**

```json
{
    "message": "Action completed successfully.",
    "result": {...}
}
```

**Examples:**

```curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "whois",
    "username": "admin",
    "password": "adminPassword",
    "user": "john_doe"
}'
```

```http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "whois", 
        username = "admin", 
        password = "adminPassword", 
        user = "john_doe" 
    }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{
    "action": "whois",
    "username": "admin",
    "password": "adminPassword",
    "user": "john_doe"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```

```curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "listISPs",
    "username": "admin",
    "password": "adminPassword"
}'
```

```http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "listISPs", 
        username = "admin", 
        password = "adminPassword" 
    }),
    { ["Content-Type"] = "application/json" }
)
```

```local internet = require("internet")
local data = [[{
    "action": "listISPs",
    "username": "admin",
    "password": "adminPassword"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "listISPs",
    "username": "admin",
    "password": "adminPassword"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "listISPs", 
        username = "admin", 
        password = "adminPassword" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "listISPs",
    "username": "admin",
    "password": "adminPassword"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "acceptRequest",
    "username": "admin",
    "password": "adminPassword",
    "ispID": "isp123"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "acceptRequest", 
        username = "admin", 
        password = "adminPassword", 
        ispID = "isp123" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "acceptRequest",
    "username": "admin",
    "password": "adminPassword",
    "ispID": "isp123"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "denyRequest",
    "username": "admin",
    "password": "adminPassword",
    "ispID": "isp123"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "denyRequest", 
        username = "admin", 
        password = "adminPassword", 
        ispID = "isp123" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "denyRequest",
    "username": "admin",
    "password": "adminPassword",
    "ispID": "isp123"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "ISPblacklist",
    "username": "admin",
    "password": "adminPassword",
    "realIP": "192.0.2.1"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "ISPblacklist", 
        username = "admin", 
        password = "adminPassword", 
        realIP = "192.0.2.1" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "ISPblacklist",
    "username": "admin",
    "password": "adminPassword",
    "realIP": "192.0.2.1"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "ping",
    "username": "admin",
    "password": "adminPassword",
    "subIP": "192.168.1.1"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "ping", 
        username = "admin", 
        password = "adminPassword", 
        subIP = "192.168.1.1" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "ping",
    "username": "admin",
    "password": "adminPassword",
    "subIP": "192.168.1.1"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "viewLogs",
    "username": "admin",
    "password": "adminPassword",
    "type": "traffic"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "viewLogs", 
        username = "admin", 
        password = "adminPassword", 
        type = "traffic" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "viewLogs",
    "username": "admin",
    "password": "adminPassword",
    "type": "traffic"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "BulkDeleteDomainByUser",
    "username": "admin",
    "password": "adminPassword",
    "userID": "user123"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "BulkDeleteDomainByUser", 
        username = "admin", 
        password = "adminPassword", 
        userID = "user123" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "BulkDeleteDomainByUser",
    "username": "admin",
    "password": "adminPassword",
    "userID": "user123"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```
```
curl -X POST http://example.com/sas \
-H "Content-Type: application/json" \
-d '{
    "action": "listUsers",
    "username": "admin",
    "password": "adminPassword"
}'
```
```
http.post(
    "http://example.com/sas",
    textutils.serializeJSON({ 
        action = "listUsers", 
        username = "admin", 
        password = "adminPassword" 
    }),
    { ["Content-Type"] = "application/json" }
)
```
```
local internet = require("internet")
local data = [[{
    "action": "listUsers",
    "username": "admin",
    "password": "adminPassword"
}]]
local request = internet.request("http://example.com/sas", data, { ["Content-Type"] = "application/json" })
for chunk in request do
    print(chunk)
end
```