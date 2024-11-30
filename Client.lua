
local base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
local charAt, indexOf = {}, {}


for i = 1, #base64chars do
    local char = base64chars:sub(i, i)
    charAt[i - 1] = char
    indexOf[char] = i - 1
end

local blshift = bit32 and bit32.lshift or bit.blshift
local brshift = bit32 and bit32.rshift or bit.brshift
local band = bit32 and bit32.band or bit.band
local bor = bit32 and bit32.bor or bit.bor
local function base64Encode(data)
    local bytes = {string.byte(data, 1, #data)}
    local out = {}
    local b

    for i = 1, #bytes, 3 do
        b = brshift(band(bytes[i], 0xFC), 2)
        out[#out + 1] = charAt[b]
        b = blshift(band(bytes[i], 0x03), 4)

        if i + 0 < #bytes then
            b = bor(b, brshift(band(bytes[i + 1], 0xF0), 4))
            out[#out + 1] = charAt[b]
            b = blshift(band(bytes[i + 1], 0x0F), 2)

            if i + 1 < #bytes then
                b = bor(b, brshift(band(bytes[i + 2], 0xC0), 6))
                out[#out + 1] = charAt[b]
                b = band(bytes[i + 2], 0x3F)
                out[#out + 1] = charAt[b]
            else
                out[#out + 1] = charAt[b] .. "="
            end
        else
            out[#out + 1] = charAt[b] .. "=="
        end
    end

    return table.concat(out)
end
local function base64Decode(data)
    if not data then return "DECODING FAILED: Data is null" end

    local decoded = {}
    local inChars = {}
    for char in data:gmatch(".") do
        inChars[#inChars + 1] = char
    end
    for i = 1, #inChars, 4 do
        local b = {
            indexOf[inChars[i]] or 0,
            indexOf[inChars[i + 1]] or 0,
            indexOf[inChars[i + 2]] or 64,
            indexOf[inChars[i + 3]] or 64
        }

        decoded[#decoded + 1] = bor(blshift(b[1], 2), brshift(b[2], 4)) % 256
        if b[3] < 64 then
            decoded[#decoded + 1] = bor(blshift(b[2], 4), brshift(b[3], 2)) % 256
            if b[4] < 64 then
                decoded[#decoded + 1] = bor(blshift(b[3], 6), b[4]) % 256
            end
        end
    end

    return string.char(table.unpack(decoded))
end

--[[Config here]]
serverURL = "http://10.0.1.2:7080"
userID = nil
subIP = nil
publicDir = "public"
--=============================
if not fs.exists(publicDir) then
    fs.makeDir(publicDir)
end

function httpPost(endpoint, data)
    local response= http.post(serverURL .. endpoint, textutils.serializeJSON(data), {
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

function handleGetRequest(fromSubIP, path, requestID)
    path = base64Decode(path)
    if not path or path:find(publicDir.."/", 1, true) then
        return {
            status = 400,
            message = base64Encode("400: Invalid or unsafe file path"),
            requestID = requestID
        }
    end

    local filePath = fs.combine(publicDir, path)
    local response = {}
    if fs.exists(filePath) and not fs.isDir(filePath) then
        local file, err = fs.open(filePath, "r")
        if not file then
            response = {
                status = 500,
                message = base64Encode("500: Internal Server Error - " .. err),
                requestID = requestID
            }
        else
            local content = file.readAll()
            file.close()

            response = {
                status = 200,
                message = base64Encode("FILE:" .. base64Encode(content)),
                requestID = requestID
            }
        end
    else
        response = {
            status = 404,
            message = base64Encode("404: File not found"),
            requestID = requestID
        }
    end
    return response
end



function handlePostRequest(fromSubIP, path, data, requestID)
    if not path or path:find("public/", 1, true) then
        return {
            status = 400,
            message = base64Encode("400: Invalid or unsafe file path"),
            requestID = requestID
        }
    end

    local filePath = fs.combine(publicDir, base64Decode(path))
    local decodedData = base64Decode(data)

    if not decodedData then
        return {
            status = 400,
            message = base64Encode("400: Invalid data"),
            requestID = requestID
        }
    end

    local response = {}
    local file, err = fs.open(filePath, "w")
    if not file then
        response = {
            status = 500,
            message = base64Encode("500: Internal Server Error - " .. err),
            requestID = requestID
        }
    else
        file.write(decodedData)
        file.close()

        response = {
            status = 201,
            message = base64Encode("201: File created"),
            requestID = requestID
        }
    end
    return response
end


function handleReverseRequest(log)
        if not (log.message and log.from and log.requestID) then
            return {
                status = 400,
                message = base64Encode("400: Bad Request - Missing required fields"),
                requestID = log.requestID
            }
        end
    
        local decodedMessage = base64Decode(log.message)
        if not decodedMessage then
            return {
                status = 400,
                message = base64Encode("400: Bad Request - Invalid message encoding"),
                requestID = log.requestID
            }
        end

        local method, path, data = decodedMessage:match("([^:]+):([^|]*)|?(.*)")
        if not method or not path then
            return {
                status = 400,
                message = base64Encode("400: Bad Request - Malformed message"),
                requestID = log.requestID
            }
        end
    
        local response
        if method == "GET" then
            response = handleGetRequest(log.from, path, log.requestID)
        elseif method == "POST" then
            response = handlePostRequest(log.from, path, data, log.requestID)
        else
            response = {
                status = 400,
                message = base64Encode("400: Bad Request - Unsupported method"),
                requestID = log.requestID
            }
        end
    
        return response
    end
    
    function sendMessage()
        if not userID then
            print("Please log in first!")
            return
        end
    
        print("Enter the target Sub-IP:")
        local targetSubIP1 = read()
    
        print("Enter your message:")
        local message = read()

        if targetSubIP1 == "" or message == "" then
            print("Error: Target Sub-IP and message are required.")
            return
        end
        httpPost("/send", {
            fromUserID = userID,
            targetSubIP = targetSubIP1,
            message = base64Encode(message),
            requestID = subIP
        }
    )
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


function listen()
    while true do
        if userID then
            local response, err = httpPost("/listen", { userID = userID })
            if response and response.logs then
                for _, log in ipairs(response.logs) do
                    if log.from and log.message then
                        local decodedMessage = base64Decode(log.message)
                        if log.message and log.from and log.requestID then
                            local reverseResponse = handleReverseRequest(log)
                            if reverseResponse then
                                httpPost("/send", {
                                    fromUserID = userID,
                                    targetSubIP = log.from,
                                    message = reverseResponse.message,
                                    requestID = reverseResponse.requestID
                                })
                            end
                        else
                            if log.requestID and log.from then
                                if decodedMessage:sub(1, 5) == "FILE:" then
                                    local fileContent = base64Decode(decodedMessage:sub(6))
                                    print("File Content Received:\n" .. fileContent)
                                else
                                    print("Response Message Received:\n" .. decodedMessage)
                                end
                                print("Response ID:", log.requestID)
                            elseif decodedMessage:sub(1, 5) == "FILE:" then
                                local fileContent = base64Decode(decodedMessage:sub(6))
                                print("Received file content from", log.from, ":")
                                print(fileContent)
                            elseif decodedMessage == "ping" then
                                print("Received Ping from: ".. log.from)
                                httpPost("/send", {
                                    fromUserID = userID,
                                    targetSubIP = log.from,
                                    message = base64Encode("pong")
                                })
                            elseif decodedMessage == "pong" then
                                print("Received Pong from: " .. log.from)
                            else
                                print("Unexpected message received from", log.from, ":", decodedMessage)
                            end
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

local function redirectDomain()
    print("Enter the domain name to redirect:")
    local domain = read()
    print("Enter the target Sub-IP or domain:")
    local target = read()

    if not userID then
        print("Please log in to redirect a domain.")
        return
    end

    local response, err = httpPost("/domain/redirect", {
        domain = base64Encode(domain),
        ownerUserID = userID,
        targetSubIP = target
    })

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
        newOwnerUsername = base64Encode(recipientUsername)
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
        print("9. Send Message")
        print("10. SAS Commands")
        print("11. Exit")
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
            sendMessage()
        elseif choice == "10" then
            sasMenu()
        elseif choice == "11" then
            print("Goodbye!")
            break
        else
            print("Invalid option!")
        end
    end
end

function sasMenu()
    while true do
        print("\nSAS Commands Menu:")
        print("1. List ISPs")
        print("2. Accept ISP Request")
        print("3. Deny ISP Request")
        print("4. WHOIS Lookup")
        print("5. Blacklist ISP")
        print("6. Ping Sub-IP")
        print("7. View Logs")
        print("8. Bulk Delete Domains by User")
        print("9. List Users")
        print("10. Register ISP")
        print("11. Back to Main Menu")
        print("Choose an option:")
        local choice = read()

        if choice == "1" then
            sasListISPs()
        elseif choice == "2" then
            sasAcceptRequest()
        elseif choice == "3" then
            sasDenyRequest()
        elseif choice == "4" then
            sasWhois()
        elseif choice == "5" then
            sasBlacklistISP()
        elseif choice == "6" then
            sasPingSubIP()
        elseif choice == "7" then
            sasViewLogs()
        elseif choice == "8" then
            sasBulkDeleteDomainsByUser()
        elseif choice == "9" then
            sasListUsers()
        elseif choice == "10" then
            sasRegisterISP()
        elseif choice == "11" then
            print("Returning to Main Menu.")
            break
        else
            print("Invalid option!")
        end
    end
end


function sasRegisterISP()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter ISP Sub-IP Prefix (e.g., 192.):")
    local subIPPrefix = read()
    print("Enter ISP Real IP:")
    local realIP = read()
    print("Enter ISP Port:")
    local port = tonumber(read())
    local knownISPsInput = read()
    local knownISPs = knownISPsInput ~= "" and textutils.unserializeJSON(knownISPsInput) or {}

    local response, err = httpPost("/isp/register", {
        ispID = nil, -- Let the server generate if not provided
        subIPPrefix = subIPPrefix,
        realIP = realIP,
        port = port,
        domains = "",
        knownISPs = knownISPs
    })

    if response then
        print("Register ISP Response:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end


function sasListISPs()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "listISPs"
    })
    if response then
        print("Known ISPs:", textutils.serialize(response.knownISPs))
        print("Unknown ISPs:", textutils.serialize(response.unknownISPs))
    else
        print("Error:", err)
    end
end

function sasAcceptRequest()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter ISP ID to accept:")
    local ispID = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "acceptRequest",
        ispID = ispID
    })

    if response then
        print("Accept Request Response:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end

function sasDenyRequest()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter ISP ID to deny:")
    local ispID = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "denyRequest",
        ispID = ispID
    })

    if response then
        print("Deny Request Response:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end


function sasWhois()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter target (Sub-IP or ISP ID):")
    local target = read()

    local requestPayload = {
        username = username,
        password = password,
        action = "whois"
    }
    if target:match("^%d+%.%d+%.%d+%.%d+$") then
        requestPayload.subIP = target
    elseif target:match("^[a-f0-9%-]+$") then
        requestPayload.ispID = target
    else
        print("Invalid target format. Must be a valid Sub-IP or ISP ID.")
        return
    end
    local response, err = httpPost("/sas", requestPayload)

    if response then
        print("WHOIS Response:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end


function sasBlacklistISP()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter ISP Real IP to blacklist:")
    local realIP = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "ISPblacklist",
        realIP = realIP
    })

    if response then
        print("Blacklist Response:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end

function sasPingSubIP()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter target Sub-IP:")
    local subIP = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "ping",
        subIP = subIP
    })

    if response then
        print("Ping Response:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end

function sasViewLogs()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter log type (traffic):")
    local logType = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "viewLogs",
        type = logType
    })

    if response then
        print("Logs:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end

function sasBulkDeleteDomainsByUser()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()
    print("Enter User ID to delete domains for:")
    local userID = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "BulkDeleteDomainByUser",
        userID = userID
    })

    if response then
        print("Bulk Delete Response:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end

function sasListUsers()
    print("Enter admin username:")
    local username = read()
    print("Enter admin password:")
    local password = read()

    local response, err = httpPost("/sas", {
        username = username,
        password = password,
        action = "listUsers"
    })

    if response then
        print("Users List:", textutils.serialize(response))
    else
        print("Error:", err)
    end
end

function run()
    parallel.waitForAny(listen, mainMenu)
end

run()
