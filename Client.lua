local base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
local charAt, indexOf = {}, {}
 
local blshift = bit32 and bit32.lshift or bit.blshift
local brshift = bit32 and bit32.rshift or bit.brshift
local band = bit32 and bit32.band or bit.band
local bor = bit32 and bit32.bor or bit.bor
 
for i = 1, #base64chars do
    local char = base64chars:sub(i,i)
    charAt[i-1] = char
    indexOf[char] = i-1
end
 
local function base64Encode(data)
    local bytes = {string.byte(data, 1, #data)}
    local out = {}
    local b
    for i = 1, #bytes, 3 do
        b = brshift(band(bytes[i], 0xFC), 2)
        out[#out+1] = charAt[b]
        b = blshift(band(bytes[i], 0x03), 4)
        if i+0 < #bytes then
            b = bor(b, brshift(band(bytes[i+1], 0xF0), 4))
            out[#out+1] = charAt[b]
            b = blshift(band(bytes[i+1], 0x0F), 2)
            if i+1 < #bytes then
                b = bor(b, brshift(band(bytes[i+2], 0xC0), 6))
                out[#out+1] = charAt[b]
                b = band(bytes[i+2], 0x3F)
                out[#out+1] = charAt[b]
            else
                out[#out+1] = charAt[b].."="
            end
        else
            out[#out+1] = charAt[b].."=="
        end
    end
    return table.concat(out)
end

local function base64Decode(data)
    if not data then return "DECODING FAILED: Data is null" end
    local decoded = {}
    local inChars = {}
    for char in data:gmatch(".") do
        inChars[#inChars+1] = char
    end
    for i = 1, #inChars, 4 do
        local b = {indexOf[inChars[i]], indexOf[inChars[i+1]], indexOf[inChars[i+2]], indexOf[inChars[i+3]]}
        decoded[#decoded+1] = bor(blshift(b[1], 2), brshift(b[2], 4)) % 256
        if b[3] < 64 then
            decoded[#decoded+1] = bor(blshift(b[2], 4), brshift(b[3], 2)) % 256
            if b[4] < 64 then
                decoded[#decoded+1] = bor(blshift(b[3], 6), b[4]) % 256
            end
        end
    end
    return string.char(table.unpack(decoded))
end

-- Configuration
serverURL = "http://10.0.1.2:7080"
userID = nil
subIP = nil
publicDir = "public"

if not fs.exists(publicDir) then
    fs.makeDir(publicDir)
end

function httpPost(endpoint, data)
    local response = http.post(serverURL .. endpoint, textutils.serializeJSON(data), {
        ["Content-Type"] = "application/json"
    })
    if response then
        local body = response.readAll()
        response.close()
        return textutils.unserializeJSON(body)
    else
        return nil, "HTTP request failed"
    end
end

function handleGetRequest(fromSubIP, path)
    local filePath = fs.combine(publicDir, path)

    if fs.exists(filePath) and not fs.isDir(filePath) then
        local file = fs.open(filePath, "r")
        local content = file.readAll()
        file.close()

        -- Ensure the file content is properly encoded and prefixed
        httpPost("/send", {
            fromUserID = userID,
            targetSubIP = fromSubIP,
            message = base64Encode("FILE:" .. base64Encode(content))
        })
    else
        httpPost("/send", {
            fromUserID = userID,
            targetSubIP = fromSubIP,
            message = base64Encode("404: File not found")
        })
    end
end

function handlePostRequest(fromSubIP, path, data)
    print("From: " .. fromSubIP .. " PATH: " .. path .. " data: \n" ..data)
    local filePath = fs.combine(publicDir, base64Decode(path))
    local decodedData = base64Decode(data)
    if not decodedData then return end

    local file = fs.open(filePath, "w")
    file.write(decodedData)
    file.close()

    httpPost("/send", {
        fromUserID = userID,
        targetSubIP = fromSubIP,
        message = base64Encode("201: File created")
    })
end

function handleReverseRequest(log)
    if log.message and log.from then
        local decodedMessage = base64Decode(log.message)
        if not decodedMessage:match("^[^:]+:.+") then return end

        local parts = {}
        for part in string.gmatch(decodedMessage, "([^:|]+)") do
            table.insert(parts, part)
        end

        local method = parts[1]
        local path = parts[2]
        local data = parts[3]
        if method == "GET" then
            handleGetRequest(log.from, path)
        elseif method == "POST" then
            handlePostRequest(log.from, path, data)
        end
    end
end

function login()
    print("Enter your username:")
    username = read()
    print("Enter your password:")
    password = read("*")

    local response, err = httpPost("/login", {
        username = base64Encode(username),
        password = base64Encode(password)
    })

    if response then
        if response.subIP and response.userID then
            userID = response.userID
            subIP = response.subIP
            print("Logged in successfully!")
            print("Sub-IP:", subIP)
            print("User ID:", userID)
        end
    end
end

-- Listen for Messages
function listen()
    while true do
        if userID then
            local response, err = httpPost("/listen", { userID = userID })
            if response and response.logs then
                for _, log in ipairs(response.logs) do
                    if log.from and log.message then
                        local decodedMessage = base64Decode(log.message)

                        if decodedMessage:sub(1, 5) == "FILE:" then
                            -- Extract the file content by removing the "FILE:" prefix
                            local fileContent = base64Decode(decodedMessage:sub(6))
                            print("Received file content from", log.from, ":")
                            print(fileContent) -- Print the file content
                        elseif decodedMessage == "ping" then
                            print("Received ping from", log.from)
                            local pongResponse, pongErr = httpPost("/send", {
                                fromUserID = userID,
                                targetSubIP = log.from,
                                message = base64Encode("pong")
                            })
                            if not pongResponse then
                                print("Error sending pong:", pongErr)
                            end
                        elseif decodedMessage == "pong" then
                            print("Received pong from", log.from)
                        else
                            handleReverseRequest(log)
                        end
                    end
                end
            else
                print("Error listening for messages:", err)
            end
        end
        sleep(5)
    end
end


function pingTarget()
    print("Enter target Sub-IP to ping:")
    local targetSubIP = read()
    if not userID then return end
    httpPost("/send", {
        fromUserID = userID,
        targetSubIP = targetSubIP,
        message = base64Encode("ping")
    })
end

function simulateWebRequest()
    print("\nSimulate Web Request:")
    print("1. GET")
    print("2. POST")
    local choice = read()

    if choice == "1" then
        print("Enter target Sub-IP:")
        local targetSubIP = read()
        print("Enter file path:")
        local path = read()

        httpPost("/reverse", {
            fromUserID = userID,
            targetSubIP = targetSubIP,
            method = "GET",
            path = base64Encode(path)
        })
    elseif choice == "2" then
        print("Enter target Sub-IP:")
        local targetSubIP = read()
        print("Enter file path:")
        local path = read()
        print("Enter file content:")
        local data = read()

        httpPost("/reverse", {
            fromUserID = userID,
            targetSubIP = targetSubIP,
            method = "POST",
            path = base64Encode(path),
            data = base64Encode(data)
        })
    end
end
-- Register a new user
local function register()
    print("Enter a username:")
    username = read()
    print("Enter a password:")
    password = read("*")

    local response, err = httpPost("/register", {
        username = base64Encode(username),
        password = base64Encode(password)
    })

    if response then
        if response.subIP and response.userID then
            userID = response.userID
            subIP = response.subIP
            print("Registered successfully!")
            print("Sub-IP:", subIP)
            print("User ID:", userID)
        else
            print("Error:", response.error or "Unknown error")
        end
    else
        print("Error:", err)
    end
end

-- Function to register a new domain
local function registerDomain()
    print("Enter the domain name to register:")
    local domain = read()

    if not userID then
        print("Please log in to register a domain.")
        return
    end

    local response, err = httpPost("/domain/register", {
        ownerUserID = userID,
        domain = base64Encode(domain)
    })

    if response then
        print("Domain registered successfully:", domain)
    else
        print("Error registering domain:", err)
    end
end

-- Function to redirect a domain
local function redirectDomain()
    print("Enter the domain name to redirect:")
    local domain = read()
    print("Enter the target Sub-IP or domain:")
    local target = read()

    if not userID then
        print("Please log in to redirect a domain.")
        return
    end

    -- Send the request to the server
    local response, err = httpPost("/domain/redirect", {
        domain = base64Encode(domain),  -- Base64 encode the domain
        ownerUserID = userID,           -- Ensure the correct userID is sent
        targetSubIP = target            -- The target for redirection
    })

    -- Handle the response
    if response then
        if response.message then
            print("Domain redirected successfully:", domain)
        else
            print("Error:", response.error or "Unknown error")
        end
    else
        print("Error redirecting domain:", err)
    end
end


-- Function to query a domain
local function queryDomain()
    print("Enter the domain name to query:")
    local domain = read()
    if not userID then
        print("Please log in to query a domain.")
        return
    end
    local response, err = httpPost("/domain/query", {
        ownerUserID = userID,
        domain = base64Encode(domain)
    })

    if response then
        print("Domain:", domain)
        print("Owner:", response.ownerUsername)
        if response.redirect then
            print("Redirect:", response.redirect)
        else
            print("Redirect: None")
        end
    else
        print("Error querying domain:", err)
    end
end

-- Function to transfer a domain
local function transferDomain()
    print("Enter the domain name to transfer:")
    local domain = read()
    print("Enter the username of the recipient:")
    local recipientUsername = read()

    if not userID then
        print("Please log in to transfer a domain.")
        return
    end

    local response, err = httpPost("/domain/transfer", {
        domain = base64Encode(domain),
        currentOwnerUserID = userID,
        newOwnerUsername = base64Encode(recipientUsername) -- Encode the recipient username
    })

    if response then
        print("Domain transferred successfully:", domain, "to", recipientUsername)
    else
        print("Error transferring domain:", err)
    end
end


function mainMenu()
    while true do
        print("\nMain Menu:")
        print("1. Register")
        print("2. Log In")
        print("3. Send Ping")
        print("4. Simulate Web Request")
        print("5. Register Domain")
        print("6. Transfer Domain")
        print("7. Redirect Domain")
        print("8. Query Domain")
        print("9. Exit")
        print("Choose an option:")
        local choice = read()

        if choice == "1" then
            register()
        elseif choice == "2" then
            login()
        elseif choice == "3" then
            if not userID then
                print("Please log in first!")
            else
                pingTarget()
            end
        elseif choice == "4" then
            simulateWebRequest()
        elseif choice == "5" then
            registerDomain()
        elseif choice == "6" then
            transferDomain()
        elseif choice == "7" then
            redirectDomain()
        elseif choice == "8" then
            queryDomain()
        elseif choice == "9" then
            print("Goodbye!")
            break
        else
            print("Invalid option!")
        end
    end
end


function run()
    parallel.waitForAny(listen, mainMenu)
end

run()
