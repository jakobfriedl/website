---
title: 'Customizing C2 Traffic using Advanced Malleable Network Profiles'
date: 2026-03-05T00:00:00+01:00

footer: 'Jakob Friedl © 2026' 

categories: ['c2-dev']
blog_post: true
---

One of the primary ways C2 communication is getting detected by defenders is by patterns in the network traffic between team server and agents. To counter this, modern post-exploitation frameworks, including [**Conquest**](https://github.com/jakobfriedl/conquest/), provide the ability to customize this network traffic using malleable C2 profiles. Using simple configuration files, operators can transform HTTP requests and responses according to their needs. This blog post aims to showcase Conquest's profile system and all the features it provides.
<!--more-->

## Malleable C2

The concept of *Malleable C2* was introduced with Cobalt Strike 2.0 over ten years ago in 2014. In essence, a malleable C2 profile allows an operator to specify how data is transformed and stored in a transaction, such as a checkin or task result. Hence, it pretty much allows for a full customization of the agent's network traffic indicators, such as HTTP endpoints, request and response headers and contents. Through this customization, red teamers can design their profiles in a way that makes their implant's network footprint blend in with the target infrastructure. On top of that, malleable C2 profiles can be used to deliberately emulate known threat actors in order to test a client's detection capabilities against real adversaries[^1]. Cobalt Strike's Malleable C2 uses a custom profile language[^2] to change how the Beacon's network traffic looks like and what default post-exploitation options are configured. In Conquest, profiles are represented as TOML configuration files, following a structure that is outlined in the subsequent sections.

## Basic Settings

Conquest profiles fully support the version 1.1 spec of the TOML configuration language and are primarily used to customize network traffic using a combination of data transformation, encoding and randomization. First, however, basic team server settings need to be specified. As these fields are required, the beginning of all Conquest profiles is structured in the following way.

| Key | Type | Description | 
| -- | -- | -- |
| *`name`* | `string` | Name of the profile. | 
| *`private-key-file`* | `string` | Relative path to the team server's X25519 private key. | 
| *`database-file`* | `string` | Relative path to the location of the Conquest database. | 
| *`team-server.host`* | `string` | Address that the team server listens on for client connections (default: 0.0.0.0). |
| *`team-server.port`* | `int` | Port that the team server listens on for client connections (default: 37573). |
| *`team-server.users`* | `array` | List of users that can authenticate to the team server. A user object consists of a username and password. |

```toml {lineNos=table}
name = "cq-default-profile"

private-key-file = "data/keys/conquest-server_x25519_private.key"
database-file = "data/conquest.db"

[team-server]
host = "0.0.0.0"
port = 37573
users = [
    { username = "jakob", password = "conquest" }, 
    { username = "operator", password = "conquest" }
]
```

## HTTP Traffic Customization

With the basic settings out of the way, let's now direct our attention to the key feature Conquest's profile system has to offer: the *HTTP traffic customization*. The settings are divided into two main sections that both offer similar configuration options: `http-get` settings and `http-post` settings. These sections are then split into the additional `agent` and `server` blocks. The `agent` block allows the customization of the requests sent by the C2 implant, while `server` options are used to define the shape of the response sent back by the team server. All sections support the configuration of URI endpoints, user-agents, HTTP headers and query parameters, as well as additional settings following the high-level structure below. 

```text
 http-get
 ├── agent
 │   ├── user-agent
 │   ├── endpoints
 │   ├── headers
 │   ├── query parameters
 │   └── heartbeat 
 └── server
     ├── headers
     └── response body

 http-post
 ├── agent
 │   ├── user-agent
 │   ├── endpoints
 │   ├── request methods
 │   ├── headers
 │   ├── query parameters
 │   └── request body
 └── server
     ├── headers
     └── response body
```

While the sections responsible for agent registration and task results is labeled `http-post`, different request methods, such as PUT or GET are also supported and can be used by supplying them in form of an array instead of a string. For each request, one of them is picked based on the randomization outlined in the next section.

```toml {lineNos=table}
[http-post]
request-methods = [
    "POST",
    "PUT",
    "GET"
]
```

### Randomization 

Randomization can be enabled in different ways using Conquest's profile system. First and foremost, wildcard characters can be used anywhere - with the exception of URI endpoints - to create randomized strings. Two types of randomizers are available: 

- *`#`* : Alphanumeric character substitution (a-zA-Z0-9)
- *`$`* : Digit substitution (0-9)

Additionally, fields that usually expect a single string value can take a list of strings instead. In case an array is passed as the value of an option, a random member is chosen with each HTTP request from the list. This makes it possible to randomize HTTP header values, query parameters and even request endpoints. On the team server, a valid route is created for each endpoint in the list, while the agent randomly selects one route it sends the request to. This helps to break up repetitive and suspicious network traffic patterns. 

The profile code below shows an example for how randomization can be applied to query parameters in a GET request.

```toml {lineNos=table}
[http-get]
endpoints = [               # <--- Agent selects either /get or /api/v1.2/status.js for GET requests
    "/get",
    "/api/v1.2/status.js"
]

[http-get.agent.parameters]
id = "#####-#####"          # <--- ID string consisting of random alphanumerical characters
lang = [                    # <--- The query parameter 'lang' either has the value 'en-US' or 'de-AT' 
    "en-US",
    "de-AT"
]
page = "1$"                 # <--- Randomized page number: 10-19
```

![Randomization](/img/c2-profile-system/1.png "Query parameter and endpoint randomization.")

### Data Transformation

Randomization is also essential for the most powerful aspect of Conquest's HTTP traffic customization: *data transformation*. In a nutshell, data transformation allows the operator to configure how packets of the Conquest C2 protocol (which are explained [here](https://jakobfriedl.github.io/blog/nim-c2-traffic/)) are placed and hidden within the HTTP request or response. To recap the previous blog post briefly, the agent includes a *heartbeat* packet within the GET request. The server returns all *tasks* as the response to this request if any are found in the agent's task queue. Once the task execution is completed, the *result* is sent as another request to the team server for processing. Finally, there is also the *registration* packet, which is structurally similar to the task result.

Data transformation consists of three steps. First, these steps are executed in regular order to embed the packet data into the request/response. To extract the data from the request/response, the order of operations is reversed. 

1. **Encoding**
2. **Prepending/Appending**
3. **Placement**

#### Encoding

Encoding is used to turn the binary data of a C2 packet into a readable string in order to blend in with regular network traffic. Multiple encodings can be applied to a packet by defining them in an array of inline-tables, as seen in the example below. The encodings are applied in the order they are defined in the profile. During the decoding of the data transformation, this order is reversed. Currently, Conquest supports 5 encoding types:

- *`none`* : No encoding is applied and the packet remains in raw binary format. 
- *`base64`* : The binary data is base64-encoded. Setting the optional *`encoding.url-safe`* key to `true` will use the characters `-` and `_` instead of `+`, `=` and `/`.
- *`hex`* : The binary data is hex-encoded.
- *`xor`* : The binary data is XOR-encoded with the key specified in *`encoding.key`*.
- *`rot`* : The binary data is ROT-encoded (Caesar Cipher) with the key specified in *`encoding.key`*. 

The example below demonstrates how multiple of these encoding types can be chained together.

```toml {lineNos=table}
encoding = [
    { type = "xor", key = 5 },
    { type = "hex" },
    { type = "base64", url-safe = true }
]
```

#### Prepending/Appending

With the binary data encoded, it is now time to make it look like it belongs in the HTTP packet. This is done by prepending and/or appending strings or binary data to create a context. For instance, the following data transformation block turns the heartbeat message into a string that resembles a JWT token. Placed inside the `Authorization` header, this simple transformation can make the payload incredibly difficult to spot without knowledge of the profile configuration, as can be seen on the screenshot below. Of course, the `prepend` and `append` keys support randomization as well. 

```toml {lineNos=table}
[http-get.agent.heartbeat]
placement = { type = "header", name = "Authorization" }
encoding = { type = "base64", url-safe = true }
prepend = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
append = ".######################################-####"
```

![Heartbeat packet disguised as a JWT Bearer token](/img/c2-profile-system/0.png "Heartbeat packet disguised as a JWT Bearer token.")

Conquest also supports binary prefixes and suffixes. Instead of a string, an array of integers/bytes is used instead. This is particularly useful for mimicking binary file formats, such as images or PDFs, by prepending and appending the appropriate magic bytes, as shown in the example below.

```toml {lineNos=table}
[http-get.agent.heartbeat]
placement = { type = "body" }
encoding = { type = "xor", key = 100 }
prepend = [0x25, 0x50, 0x44, 0x46]          # <--- %PDF
append = [0x25, 0x25, 0x45, 0x4F, 0x46]     # <--- %%EOF
```

#### Placement 

Finally, the packet data needs to be placed somewhere within the request or response. Conquest supports three placement types, some of which were already mentioned in the previous sections.

- *`body`* : Payload is placed in the request body.
- *`header`* : Payload is placed in a specified HTTP header. Requires the *`placement.name`* key to be set.
- *`query`* : Payload is placed in a specified HTTP query parameter. Requires the *`placement.name`* key to be set.

When it comes to retrieving data from the HTTP request or response, the order of the aforementioned steps is reversed. First, the transformed string is retrieved from the location it was placed in, the prefix and suffix are stripped and finally the encodings are reversed. What remains is the binary packet that can then be decompressed, decrypted and parsed by the recipient. Here are some examples on how data transformation can be used to hide C2 traffic within benign structures.

```toml {lineNos=table}
# Heartbeat in PHPSESSID Cookie
[http-get.agent.heartbeat]
placement = { type = "header", name = "Cookie" }
encoding = { type = "base64", url-safe = true }
prepend = "PHPSESSID="
append = ", path=/"

# Heartbeat in query parameter mimicking Windows error telemetry upload
[http-get.agent.heartbeat]
placement = { type = "query", name = "cab" }
encoding = [
    { type = "xor", key = 31 },
    { type = "hex" }
]
prepend = "##########"
append = ".cab"

# Tasks returned as Microsoft Graph API response body
[http-get.server.output]
placement = { type = "body" }
encoding = { type = "base64", url-safe = true }
prepend = '{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users","value":"'
append = '"}'

# Task result hidden as ZIP file
[http-post.agent.output]
placement = { type = "body" }
encoding = [
    { type = "xor", key = 7 },
    { type = "rot", key = 13 }
]
prepend = [0x50, 0x4B, 0x03, 0x04]
append = [0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00]
```

## Example: youtube.profile

Putting it all together, the following snippet shows a complete profile emulating YouTube video browsing traffic. It was built by capturing real browser traffic and identifying the most realistic structures to hide C2 data in. 

Agent check-ins are sent as GET requests to `/watch` with a randomized `v` parameter mimicking a video ID. The heartbeat is base64-encoded and placed inside the Cookie header as the VISITOR_PRIVACY_METADATA value, surrounded by realistic YouTube session cookies. The server wraps its response in the opening of an actual YouTube HTML page, with the task data embedded as the content of an `origin-trial` meta tag. Task results are exfiltrated via POST requests to one of three YouTube internal API endpoints, selected randomly per request. The result data is embedded as the `appInstallData` field inside a JSON request body. The server responds with a minimal but valid responseContext object, just as the real API would.

```toml {lineNos=table}
# Conquest youtube video profile 
name = "youtube-video-profile"

# Important file paths and locations
private-key-file = "data/keys/conquest-server_x25519_private.key"
database-file = "data/conquest.db"

# Team server settings (WebSocket server port, users, ...)
[team-server]
host = "0.0.0.0"
port = 37573
users = [
    { username = "operator", password = "conquest" }
]

# ----------------------------------------------------------
# HTTP GET 
# ----------------------------------------------------------
[http-get]
user-agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
endpoints = [
    "/watch"
]

# Heartbeat is hidden as a Youtube cookie
[http-get.agent.heartbeat]
placement = { type = "header", name = "Cookie" }
encoding = { type = "base64", url-safe = true }
prepend = 'YSC=###########; SOCS=##############################################; VISITOR_PRIVACY_METADATA='
append = '; __Secure-1PSIDTS=sidts-#######_##########################################_#########################; __Secure-3PSIDTS=sidts-#######_##########################################_#########################; HSID=####################;'

[http-get.agent.parameters]
v = "###########"

[http-get.agent.headers]
Host = "www.youtube.com"
Sec-Ch-Ua = '"Not.A/Brand";v="99", "Chromium";v="136"'
Sec-Ch-Ua-Mobile = "?0"
Sec-Ch-Ua-Full-Version = '""'
Sec-Ch-Ua-Arch = '""'
Sec-Ch-Ua-Platform = '"Windows"'
Sec-Ch-Ua-Platform-Version = '""'
Sec-Ch-Ua-Model = '""'
Sec-Ch-Ua-Bitness = '""'
Sec-Ch-Ua-Wow64 = "?0"
Accept-Language = [
    "en-US,en;q=0.9",
    "de-AT,de;q=0.9,en;q=0.8"
]
Upgrade-Insecure-Requests = "1"
Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
Service-Worker-Navigation-Preload = "true"
Sec-Fetch-Site = "none"
Sec-Fetch-Mode = "navigate"
Sec-Fetch-User = "?1"
Sec-Fetch-Dest = "document"
Priority = "u=0, i"

[http-get.server.headers]
Content-Type = "text/html; charset=utf-8"
X-Content-Type-Options = "nosniff"
Cache-Control = "no-cache, no-store, max-age=0, must-revalidate"
Pragma = "no-cache"
Expires = "Mon, 01 Jan 1990 00:00:00 GMT"
Strict-Transport-Security = "max-age=31536000"
X-Frame-Options = "SAMEORIGIN"
Content-Security-Policy = 'require-trusted-types-for "script"'
Server = "ESF"
X-Xss-Protection = "0"
P3p = 'CP="This is not a P3P policy! See http://support.google.com/accounts/answer/151657?hl=de for more info."'
Alt-Svc = 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000'
Set-Cookie = "__Secure-YEC=##############################################################################; Domain=.youtube.com; Expires=Mon, 07-Dec-2026 11:39:54 GMT; Path=/; Secure; HttpOnly; SameSite=lax"

# Tasks are returned by the server in a HTML format, base64-encoded as script content
[http-get.server.output]
placement = { type = "body" }
encoding = { type = "base64" }
prepend = '<!DOCTYPE html><html style="font-size: 10px;font-family: Roboto, Arial, sans-serif;" lang="de-DE"><head><script data-id="_gd" nonce="iqZzTrtVB86B0KRGblxg9Q">window.WIZ_global_data = {"HiPsbb":0,"MUE6Ne":"youtube_web","MuJWjd":false};</script><meta http-equiv="origin-trial" content="'
append = '"/><script nonce="iqZzTrtVB86B0KRGblxg9Q">var ytcfg={d:function(){return window.yt&&yt.config_||ytcfg.data_||(ytcfg.data_={})},get:function(k,o){return k in ytcfg.d()?ytcfg.d()[k]:o},set:function(){var a=arguments;if(a.length>1)ytcfg.d()[a[0]]=a[1];else{var k;for(k in a[0])ytcfg.d()[k]=a[0][k]}}};window.ytcfg.set("EMERGENCY_BASE_URL", "/error_204?'

# ----------------------------------------------------------
# HTTP POST 
# ----------------------------------------------------------
[http-post]
user-agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
endpoints = [
    "/youtubei/v1/like/like",
    "/youtubei/v1/log_event",
    "/youtubei/v1/player"
]
request-methods = "POST"

[http-post.agent.headers]
Host = "www.youtube.com"
Referer = "https://www.youtube.com/watch?v=###########"
Content-Type = "application/json" 
Connection = "Keep-Alive"
Cache-Control = "no-cache"
Sec-Ch-Ua = '"Not.A/Brand";v="99", "Chromium";v="136"'
Sec-Ch-Ua-Mobile = "?0"
Sec-Ch-Ua-Full-Version = '""'
Sec-Ch-Ua-Arch = '""'
Sec-Ch-Ua-Platform = '"Windows"'
Sec-Ch-Ua-Platform-Version = '""'
Sec-Ch-Ua-Model = '""'
Sec-Ch-Ua-Bitness = '""'
Sec-Ch-Ua-Wow64 = "?0"
Cookie = 'YSC=###########; SOCS=##############################################; VISITOR_PRIVACY_METADATA=##################################################################; __Secure-1PSIDTS=sidts-#######_##########################################_#########################; __Secure-3PSIDTS=sidts-#######_##########################################_#########################; HSID=####################;'

[http-post.agent.parameters]
pretty-print = [
    "true",
    "false"
]

# Task result embedded in the appInstallData key in a JSON structure
[http-post.agent.output]
placement = { type = "body" }
encoding = { type = "base64", url-safe = true }
prepend = '{"context":{"client":{"hl":"de","gl":"AT","remoteHost":"$$.1$$.$$.1$$","deviceMake":"","deviceModel":"","visitorData":"Cgt1M016MzRrZmhTUSj12MbIBjInCgJBVBIhEh0SGwsMDg8QERITFBUWFxgZGhscHR4fICEiIyQlJiBe","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36,gzip(gfe)","clientName":"WEB","clientVersion":"2.20251107.01.00","osName":"Windows","osVersion":"10.0","originalUrl":"https://www.youtube.com/","screenPixelDensity":2,"platform":"DESKTOP","clientFormFactor":"UNKNOWN_FORM_FACTOR","configInfo":{"appInstallData":"'
append = '"},"screenDensityFloat":1.5,"userInterfaceTheme":"USER_INTERFACE_THEME_DARK","timeZone":"Europe/Vienna","browserName":"Chrome","browserVersion":"142.0.0.0","acceptHeader":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7","deviceExperimentId":"ChxOelUzTVRBeU1qQTJPVEV4TkRFNU5qUXhOQT09EPXYxsgGGPXYxsgG","rolloutToken":"CJu4u9qz64jjcxCr8dad-t-QAxjzyIbunueQAw%3D%3D","screenWidthPoints":1920,"screenHeightPoints":1065,"utcOffsetMinutes":60,"connectionType":"CONN_CELLULAR_3G","memoryTotalKbytes":"8000000","mainAppWebInfo":{"graftUrl":"https://www.youtube.com/watch?v=###########&list=RD4WIMyqBG9gs&start_radio=1","pwaInstallabilityStatus":"PWA_INSTALLABILITY_STATUS_UNKNOWN","webDisplayMode":"WEB_DISPLAY_MODE_BROWSER","isWebNativeShareAvailable":true}},"user":{"lockedSafetyMode":false},"request":{"useSsl":true,"internalExperimentFlags":[],"consistencyTokenJars":[]},"clickTracking":{"clickTrackingParams":"CJgFEKVBIhMIucGi957nkAMVneRJBx3cFhscygEErMFOaw=="},"adSignalsInfo":{"params":[{"key":"dt","value":"1762765953510"},{"key":"flash","value":"0"},{"key":"frm","value":"0"},{"key":"u_tz","value":"60"},{"key":"u_his","value":"4"},{"key":"u_h","value":"1200"},{"key":"u_w","value":"1920"},{"key":"u_ah","value":"1152"},{"key":"u_aw","value":"1920"},{"key":"u_cd","value":"24"},{"key":"bc","value":"31"},{"key":"bih","value":"1065"},{"key":"biw","value":"1905"},{"key":"brdim","value":"0,0,0,0,1920,0,1920,1152,1920,1065"},{"key":"vis","value":"1"},{"key":"wgl","value":"true"},{"key":"ca_type","value":"image"}],"bid":"ANyPxKqp2RGW0TLEXMjNbBRm6ZPDYteE8iHnYK0DaJMOiTEHrbqefZtn6qfK_MhA2-ZgnoosEwKaN8pi77jJRptRzz5Rsm-P_w"}},"target":{"videoId":"###########"},"params":"Cg0KCzRXSU15cUJHOWdzIAAyDAiJ2cbIBhCm6ueLAQ%3D%3D"}'

[http-post.server.headers]
Content-Type = "application/json; charset=utf-8"
X-Content-Type-Options = "nosniff"
Cache-Control = "no-cache, no-store, max-age=0, must-revalidate"
Pragma = "no-cache"
Expires = "Mon, 01 Jan 1990 00:00:00 GMT"
Server = "ESF"
X-Xss-Protection = "0"
Strict-Transport-Security = "max-age=31536000"
Alt-Svc = 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000'

# Server's response to task results
[http-post.server.output]
body = '{"responseContext": {}}'
```

![Youtube Profile Traffic - Tasks](/img/c2-profile-system/4.png "Tasks sent by the team server embedded in a HTML structure.")

![Youtube Profile Traffic - Results](/img/c2-profile-system/3.png "Task results sent embedded in JSON data.")

## Conclusion

While Conquest's malleable profile system was largely inspired by Cobalt Strike's implementation, using TOML as the configuration format and supporting additional data transformation features makes it a powerful tool for shaping C2 traffic into something that can slip past defenders. The profile system was also covered in my [presentation](https://cfp.bsidesvienna.at/bsidesvienna-0x7e9-2025/talk/VCQATE/) at BSidesVienna 2025, alongside the rest of the Conquest architecture. If you're interested in the Conquest framework in general, check out the project on [GitHub](https://github.com/jakobfriedl/conquest/) and give it a star ☆.

[^1]: https://www.cobaltstrike.com/product/features/malleable-c2
[^2]: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm#_Toc65482837