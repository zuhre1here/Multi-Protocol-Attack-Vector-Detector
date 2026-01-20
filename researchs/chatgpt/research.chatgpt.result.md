# Research Result for chatgpt
# Multi-Protocol Attack Vector Detector

## Introduction

Modern web applications increasingly rely on multiple communication
protocols -- from classic HTTP/1.1 to newer HTTP/2, as well as
persistent channels like WebSockets and specialized API layers like
GraphQL. Each protocol introduces unique features and potential
vulnerabilities, which attackers can exploit. For example, HTTP/2's
binary framing can lead to subtle request translation
bugs[\[1\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=research%20focuses%20on%20the%20fact,be%20created%20and%20cause%20a),
and GraphQL's powerful querying capabilities can be abused to overload
servers[\[2\]](https://graphql.org/learn/security/#:~:text=On%20this%20page%2C%20we%E2%80%99ll%20survey,GraphQL%20API%20from%20malicious%20operations).
A **Multi-Protocol Attack Vector Detector** aims to monitor and defend
across all these interfaces in a unified way. This includes leveraging
network-based intrusion detection (e.g. **Suricata**) and in-line web
application firewalls (e.g. **ModSecurity** with OWASP Core Rule Set) to
cover the full spectrum of
attacks[\[3\]](https://owasp.org/www-project-modsecurity/#:~:text=The%20OWASP%20ModSecurity%20project%20provides,brings%20protection%20against%20HTTP%20attacks).
In the sections below, we examine the attack vectors specific to
HTTP/1.1, HTTP/2, WebSockets, and GraphQL -- and how a coordinated
detection strategy can be implemented for each.

## HTTP/1.1 Attack Vectors and Detection {#http1.1-attack-vectors-and-detection}

HTTP/1.1 is the foundation of web traffic and carries well-known attack
vectors. Classic web attacks include injection flaws (SQL injection,
command injection), cross-site scripting (XSS), cross-site request
forgery (CSRF), remote file inclusion, and others. These are enumerated
in the OWASP Top 10 and are typically delivered via HTTP requests and
parameters. Attackers craft malicious inputs -- for example, an XSS
attack might embed a `<script>` tag in a parameter to hijack a victim's
browser session, or an SQL injection might use a payload like
`' OR '1'='1` to bypass authentication. Over the years, defensive
signatures for HTTP/1.1 have matured, and both IDS and WAF solutions
come with extensive rule sets to detect such patterns. **ModSecurity**
coupled with the OWASP Core Rule Set (CRS) provides broad coverage
against common HTTP/1.1 attacks
out-of-the-box[\[3\]](https://owasp.org/www-project-modsecurity/#:~:text=The%20OWASP%20ModSecurity%20project%20provides,brings%20protection%20against%20HTTP%20attacks).
Similarly, **Suricata** IDS includes many HTTP-oriented signatures to
catch malicious payloads in URIs, headers, and bodies.

Some typical HTTP/1.1 attack indicators that can be detected include:

- **SQL Injection** -- presence of SQL keywords or tautologies in inputs
  (e.g. `UNION SELECT`, `' OR 1=1--`) or SQL error messages in
  responses.
- **Cross-Site Scripting (XSS)** -- script tags or JavaScript event
  handlers in inputs (e.g. `<script>alert('XSS')</script>`).
- **Directory Traversal** -- sequences like `../` in URLs indicating
  attempts to access filesystem paths.
- **HTTP Request Smuggling** -- malformed or conflicting HTTP headers
  (e.g. duplicate `Content-Length` headers) that suggest an attempt to
  desynchronize front-end and back-end HTTP
  parsing[\[4\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=Akamai%20responded%20to%20the%20original,HTTP%20Request%20Smuggling%20such%20as).
- **Slowloris/Slow HTTP DoS** -- abnormal request patterns such as
  never-ending headers without finalizing a request, which attempt to
  exhaust server connection pools.

Detection engines use both pattern matching and anomaly detection to
flag these. For instance, the OWASP CRS contains rules that *"deny
common XSS patterns"* and *"detect SQL meta-characters"* in HTTP
requests. Suricata's HTTP parser can normalize request components and
apply content rules or PCRE (regex) matches to detect suspicious
content. Below is an example of a Suricata rule detecting an XSS payload
and a ModSecurity rule for a basic SQLi detection:

    # Suricata rule: Detect any occurrence of <script> in HTTP request (possible XSS)
    alert http any any -> any any (msg:"XSS Attack Detected"; flow:to_server; http.request_line; content:"<script>"; nocase; sid:100015;)
    # ModSecurity rule: Detect case-insensitive SQL union select pattern in query parameters (basic SQLi)
    SecRule ARGS "(?i:union\\s+select\\s+)" "id:100100,phase:2,deny,status:403,msg:'SQL Injection Attack Detected'"

These rules illustrate signature-based detection. The Suricata rule
watches outgoing HTTP requests for the string `<script>` (a simple
indicator of
XSS)[\[5\]](https://nikhil-c.medium.com/suricata-creating-rules-with-practical-scenarios-df659e87d515#:~:text=%2A%20Metasploit%20Cross,payloads%20or%20script%20injection%20patterns),
while the ModSecurity rule uses a regular expression to find the phrase
\"`UNION SELECT`\" in any request argument, a common SQL injection
fingerprint. In practice, real-world rulesets are more complex (handling
edge cases, encoding, etc.), but the principle is to leverage known
malicious patterns.

It's also important to detect **HTTP protocol anomalies**. HTTP/1.1
attack techniques like **HTTP Request Smuggling** often rely on
ambiguous or contradictory headers. For example, an incoming request
with two `Content-Length` headers or a `Content-Length` *and* a
`Transfer-Encoding: chunked` header is almost always
malicious[\[4\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=Akamai%20responded%20to%20the%20original,HTTP%20Request%20Smuggling%20such%20as).
An effective detector will flag such a request for manual review or
blocking. Many modern WAFs will outright reject requests with such
irregularities as a defensive measure. Suricata and ModSecurity rules
can similarly be written to enforce protocol compliance (e.g., alert if
a forbidden header combination is seen).

In summary, HTTP/1.1 being a plaintext, well-understood protocol means
we have a rich set of detection capabilities for its attacks. A
multi-protocol detector uses this as the first layer of defense,
leveraging the maturity of HTTP/1.1 security tools to catch known web
exploits before they escalate.

## HTTP/2 Attack Vectors and Detection

HTTP/2 was introduced to improve performance with features like binary
framing, header compression, and request multiplexing. However, these
very features have opened new avenues for attacks. HTTP/2 is not a
completely separate protocol but rather a new framing layer for HTTP
semantics. Many HTTP/1.1 attacks still apply, but the protocol's
differences can be abused in novel ways:

- **Request Smuggling via HTTP/2 to HTTP/1.1 Downgrade**: Many
  deployments terminate HTTP/2 at a front-end server or CDN, which then
  translates requests to HTTP/1.1 for back-end services. Improper
  translation can introduce smuggling vulnerabilities. Because HTTP/2
  uses a binary format with length-prefixed headers (and allows header
  names/values to contain newline characters), a naive or buggy
  translation to textual HTTP/1.1 might inject unintended
  headers[\[1\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=research%20focuses%20on%20the%20fact,be%20created%20and%20cause%20a).
  For example, researchers demonstrated that a carefully crafted HTTP/2
  header value containing `\n\nGET /malicious HTTP/1.1...` could escape
  into a new request during conversion, resulting in a classic smuggling
  attack[\[1\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=research%20focuses%20on%20the%20fact,be%20created%20and%20cause%20a).
  In other words, the front-end HTTP/2 parser must be extremely strict
  -- any gap can allow attackers to sneak in rogue requests when
  converting to HTTP/1.1. Detection of this vector involves monitoring
  for protocol translation anomalies. A multi-protocol detector can't
  directly "see" the internal translation, but it can flag suspicious
  patterns such as binary-encoded newline sequences or use of undefined
  pseudo-headers. Logging at the proxy layer is also vital: e.g.,
  Akamai's research team leveraged debug logging to confirm that their
  edge servers blocked irregular HTTP/2 sequences before they hit origin
  servers[\[6\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=concept%20tooling%20from%20CERT%2FCC%20,The%20http2smugl)[\[7\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=Error%3A%20server%20dropped%20connection%2C%20error%3Derror,code%20PROTOCOL_ERROR).

- **HTTP/2-Specific DoS Attacks**: Several denial-of-service attack
  vectors have been identified in HTTP/2 implementations. In 2019, a
  series of CVEs (sometimes dubbed "H2 Bomb" vulnerabilities) were
  disclosed -- attackers could exploit things like the **HEADERS
  flooding** (sending a huge number of small header frames), **Ping
  flooding**, or manipulating the flow-control window in a way that ties
  up server resources. More recently, in August 2023, the **"HTTP/2
  Rapid Reset"** attack (CVE-2023-44487) was observed in the
  wild[\[8\]](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487#:~:text=The%20vulnerability%20%28CVE,August%202023%20through%20October%202023).
  This attack involves a client rapidly opening thousands of HTTP/2
  streams and immediately resetting them, causing the server to do
  excessive work tracking and cleaning up streams. A coordinated botnet
  using Rapid Reset was able to generate a record-breaking DDoS of 201
  million requests per
  second[\[9\]](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/#:~:text=Starting%20on%20Aug%2025%2C%202023%2C,previous%20biggest%20attack%20on%20record)[\[10\]](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/#:~:text=This%20attack%20was%20made%20possible,facing%20web%20or%20API%20server).
  Essentially, features meant for efficient multiplexing were abused to
  amplify attack traffic. Detecting these conditions at the network
  level is challenging -- the traffic pattern (many RST_STREAM frames in
  short time) can be spotted by an IDS if it keeps track of abnormal
  rates. Indeed, vendors like Cloudflare, Google, and AWS collaborated
  to deploy mitigations that drop connections exhibiting these rapid
  resets[\[10\]](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/#:~:text=This%20attack%20was%20made%20possible,facing%20web%20or%20API%20server).
  Anomaly detection rules can be created to alert on an excessive rate
  of certain HTTP/2 frame types (e.g., an unusual volume of `RST_STREAM`
  or `GOAWAY` frames within a second).

- **HPACK Compression Attacks**: HPACK is the header compression
  algorithm used in HTTP/2. There have been theoretical attacks where an
  attacker crafts inputs to cause target servers or intermediaries to
  decompress headers in a way that consumes lots of CPU or memory
  (similar in spirit to ZIP bombs). While not widely seen, a detector
  could monitor header size and compression ratios, alerting if a single
  HTTP/2 header block decompresses to an abnormal size or if decoding
  fails integrity checks.

To detect and mitigate HTTP/2 threats, it's crucial to **enable protocol
awareness in our tools**. Suricata, for instance, added experimental
HTTP/2 parsing in version 6. By default Suricata 6.0.0 did not enable
HTTP/2 handling, but as of v6.0.4+ one can turn it on in the
configuration[\[11\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=was%20surprised%20that%20Suricata%20did,have%20the%20HTTP%2F2%20parsing%20disabled)[\[12\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=version%206,enable%20HTTP%2F2%20logging%20and%20alerting).
Key settings include enabling the HTTP/2 parser and allowing
"HTTP/1-over-HTTP/2" rule overloading:

    # Suricata (suricata.yaml) – enable HTTP/2 parsing and overload HTTP/1 rules
    app-layer:
      protocols:
        http2:
          enabled: yes            # Parse HTTP/2 traffic
          http1-rules: yes        # Apply HTTP/1 signatures to HTTP/2 streams

With `http2.enabled: yes`, Suricata will parse HTTP/2 frames (streaming
over TCP or TLS as appropriate) and reconstruct HTTP transactions. The
`http1-rules: yes` (so-called *overloading* feature) is particularly
powerful: it allows existing HTTP/1.1 content rules to automatically
apply to HTTP/2 message
components[\[13\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=alert%20http%20%24HOME_NET%20any%20,authority%3A%20example.com)[\[14\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=With%20overloading%20enabled%20via%20the,covered%20by%20a%20single%20rule).
For example, if we have a rule looking for `http.uri` or
`http.request_body` content, Suricata will check the equivalent in the
HTTP/2 streams (URI and body extracted from HEADERS and DATA frames).
This means we don't need to duplicate every rule for HTTP/2. An HTTP
attack signature like a known SQLi payload can be written once and will
match in either HTTP/1.1 or HTTP/2 traffic (provided overloading is
enabled). This greatly simplifies multi-protocol rule management.

Of course, HTTP/2 also introduces new elements that have no analog in
HTTP/1. For those, Suricata provides HTTP/2-specific keywords. For
example, rules can match on frame types (`http2.frametype`), error codes
in RST_STREAM or GOAWAY frames (`http2.errorcode`), window size updates
(`http2.window`), etc. These allow writing signatures for scenarios such
as "client attempts to set an invalid HTTP/2 setting" or "too large of a
headers table size" etc. As a simple illustration, one might create a
rule to detect a disabled server push setting:

    # Suricata rule: Alert if a client sends a SETTINGS frame disabling server push (could be benign or part of a probe)
    alert http2 any any -> any any (msg:"Client disabled HTTP/2 server push"; flow:to_server; http2.settings:SETTINGS_ENABLE_PUSH=0; sid:420001;)

Or a rule to catch an abnormally large window update request:

    alert http2 any any -> any any (msg:"HTTP/2 Window Update Flood?"; flow:to_server; http2.window:>10000000; sid:420002;)

These are hypothetical examples -- in practice, rate-based detection (to
catch floods) or specialized anomaly scoring might be more effective for
something like Rapid Reset. Still, they show how granular visibility
into HTTP/2 frames is possible. (Suricata's HTTP/2 keywords cover frame
types, flags, lengths, etc., enabling detection of specific protocol
behaviors[\[15\]](https://docs.suricata.io/en/latest/rules/http2-keywords.html#:~:text=Match%20on%20the%20frame%20type,present%20in%20a%20transaction)[\[16\]](https://docs.suricata.io/en/latest/rules/http2-keywords.html#:~:text=http2.settings%3ASETTINGS_ENABLE_PUSH%3D0%3B%20http2.settings%3ASETTINGS_HEADER_TABLE_SIZE).)

Finally, consider WAF integration. Many WAFs (including ModSecurity when
used with Apache/Nginx) work at the HTTP semantic level -- often the web
server or CDN handles the HTTP/2 decoding and passes a normalized
HTTP/1.1-like request to the WAF. It's critical that these front-ends
correctly implement HTTP/2. As noted, Akamai's platform, for instance,
terminates HTTP/2 at the edge and then processes requests with their WAF
as
HTTP/1.1[\[17\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=wide%20variety%20of%20web%20clients,then%20forwarded%20to%20the%20origin).
If that translation is correct and strict, the WAF's existing rules
suffice; if not, attacks can slip through during conversion. Therefore,
from a detection standpoint, it's wise to log or alert on any unusual
translation event. If an HTTP/2 request triggers a protocol error (e.g.,
an invalid sequence that causes a stream reset), the detector should
note this -- it could indicate someone fuzzing the HTTP/2 parser in an
attempt to find a smuggling vector. Logging anomalies (Suricata has an
*anomaly log* for protocol errors) can provide early warning of such
attempts.

**In summary**, HTTP/2 security requires handling traditional HTTP
attacks on the new framing layer and watching for entirely new
categories of attacks (mostly DoS and translation issues). A
multi-protocol detector ensures that when traffic comes in over HTTP/2,
it doesn't evade our HTTP/1.1-based signatures, and that protocol abuses
peculiar to HTTP/2 are also surveilled.

## WebSockets Attack Vectors and Detection

WebSockets enable a persistent, full-duplex communication channel
between client and server, which is a departure from the
request/response model of HTTP. After an initial HTTP handshake (an
`Upgrade: websocket` request and a `101 Switching Protocols` response),
the connection switches to the WebSocket protocol, allowing messages to
flow in both directions until the connection closes. This mechanism
greatly improves real-time communication (for example, live chats,
gaming updates,
etc.)[\[18\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=The%20WebSocket%20Protocol%2C%20standardized%20in,time%20events)[\[19\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=The%20differences%20between%20the%20traditional,terminated%2C%20requiring%20a%20new%20request).
However, the introduction of WebSockets also brings new security
considerations and attack vectors:

![](media/rId43.png){width="5.833333333333333in"
height="3.2783333333333333in"}  
*Differences between a persistent WebSocket connection and traditional
HTTP request-response. Once the WebSocket handshake is completed, the
protocol allows continuous bi-directional data flow without the overhead
of repeated HTTP requests, but also without some of HTTP's built-in
security mechanisms.*

One primary concern is **Cross-Site WebSocket Hijacking (CSWSH)**. Under
the Same-Origin Policy, normal XHR/fetch requests from a malicious site
cannot read data from another site's responses -- but WebSockets are not
automatically protected by same-origin rules in the browser. The
WebSocket handshake does include an `Origin` header, but the onus is on
the server to check
it[\[20\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=certain%20sites%20SHOULD%20verify%20the,HTTP%20403%20Forbidden%20status%20code)[\[21\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=match%20at%20L183%20does%20leave,most%20developers%20are%20unaware%20of).
If a WebSocket server fails to verify the Origin and any required auth,
a malicious webpage can initiate a WebSocket connection to the target
site *as if it were the user*. The browser will include any cookies in
this WebSocket handshake (because it's a normal HTTP upgrade request).
This means an attacker can potentially interact with the WebSocket
endpoint using the victim's session, stealing data or issuing privileged
actions, all via the user's browser. Real-world penetration tests have
frequently found this vulnerability -- developers often forget to
implement Origin checks on the server
side[\[22\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=does%20leave%20the%20Origin%20header,most%20developers%20are%20unaware%20of)[\[23\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=match%20at%20L203%20origin%20header,traffic%20in%20the%20victim%E2%80%99s%20browser).
The impact can be severe (account takeover, data exfiltration, or remote
code execution depending on what the WebSocket is used
for)[\[24\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=This%20blog%20will%20demonstrate%20how,io).

Another issue is use of **unencrypted WebSocket connections (ws://)**.
Unlike `wss://` (WebSocket Secure, which is essentially WebSockets over
TLS), unencrypted WebSockets are vulnerable to man-in-the-middle
interception and should not be used on the open Internet. If an
application were to use `ws://` in production (perhaps by
misconfiguration), an attacker on the same network path could sniff or
even inject messages. A multi-protocol detector can catch this by
noticing non-TLS WebSocket handshakes. For instance, the HTML snippet in
a page might reveal a `ws://` URL where `wss://` was
expected[\[25\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=The%20HTML%20snippet%20below%20shows,this%20would%20be%20a%20finding).
In our detector, we could flag any attempt by a client to initiate a
plaintext WebSocket if policy dictates all should be secure.

There are also potential **message-based attacks** over WebSockets.
Since WebSocket messages can carry text or binary data of any format, an
attacker might try to tunnel other attacks through it -- e.g., sending
SQL injection payloads or malware binaries over a WebSocket if they
suspect the HTTP channel is monitored. Without a capable detector,
WebSocket traffic could become a blind spot.

To secure WebSocket communications, we extend our detection to the
handshake and the message stream:

- **Handshake Monitoring**: The initial handshake is an HTTP GET request
  with `Connection: Upgrade` and `Upgrade: websocket` headers. This
  request is visible to HTTP-level tools. Our detector should verify
  that the handshake is coming from an expected origin and follows
  protocol. For example, if we see a WebSocket handshake request that
  lacks an `Origin` header (which can happen if a non-browser client is
  connecting), it could be suspicious. We might implement a rule:
  *"Alert if Upgrade: websocket and no Origin header is present"*, as
  this scenario is unusual for browser traffic and could indicate a
  script attempting CSWSH. Likewise, if the Origin is present but not
  one of the allowed domains (for servers that are supposed to only be
  used by certain origins), that should be alerted or
  blocked[\[20\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=certain%20sites%20SHOULD%20verify%20the,HTTP%20403%20Forbidden%20status%20code)[\[26\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=origin%20header%20in%20the%20HTTP,traffic%20in%20the%20victim%E2%80%99s%20browser).
  The detector can also flag usage of `ws://` (in the handshake
  Request-URI or the scheme) since in most deployments it's a
  misconfiguration if not using TLS. All these checks happen during or
  immediately after the HTTP upgrade request.

- **Message Stream Inspection**: Once the connection is upgraded,
  traffic consists of WebSocket frames. Traditional HTTP-only WAFs might
  not see this, but Suricata **does** have the capability to parse some
  WebSocket traffic at the IDS level. Suricata 7+ introduced keywords
  for WebSocket frames (e.g., `websocket.payload`,
  `websocket.opcode`)[\[27\]\[28\]](https://docs.suricata.io/en/latest/rules/websocket-keywords.html#:~:text=8).
  Our detector can use these to apply content signatures to WebSocket
  messages, similar to HTTP. For example, if we want to detect an XSS
  payload being sent through a WebSocket, we could write a rule to
  search the WebSocket payload for `<script>` tags or other malicious
  markers. If a WebSocket is being used to exfiltrate data or commands
  (as a C2 channel), we might detect known markers or abnormal binary
  blobs. Below is a simple Suricata rule example that demonstrates
  inspecting WebSocket messages:

<!-- -->

    # Suricata rule: Detect any occurrence of "<script>" in a WebSocket text message (opcode 1 = text)
    alert websocket any any -> any any (msg:"Suspicious script tag in WebSocket message"; websocket.opcode:1; websocket.payload; content:"<script>"; nocase; sid:420010;)

This rule checks for text frames (`opcode:1`) and searches the unmasked
payload for the string `<script>`. In a real deployment, one might
refine this (e.g., only alert on frames from client to server, etc.),
but it illustrates that the detector can look *inside* WebSocket
traffic. Suricata's config option `websocket.max-payload-size` sets how
much of each message to capture for
analysis[\[27\]](https://docs.suricata.io/en/latest/rules/websocket-keywords.html#:~:text=8)
-- extremely large messages might be truncated for performance, but
typical messages (chat texts, small JSONs, etc.) can be fully inspected.

- **Rate/Behavior Anomalies**: Because WebSockets allow continuous
  communication, we should also watch for abnormal behavior over a
  connection. For instance, a client that opens a WebSocket and then
  sends a flood of binary data or a sequence of rapid-fire small
  messages could indicate a DoS attempt or malicious activity (like
  brute forcing something via the WebSocket). If our detector sees 1000
  messages within a few seconds on a single WebSocket, it could raise an
  alert for rate anomaly. Suricata's thresholding and flow tracking can
  assist here (though configuring that for WebSocket frames may require
  custom scripting or future enhancements).

From a **defensive** standpoint, the best mitigation for CSWSH is for
the server to validate the Origin header on handshake and enforce
authentication on the WebSocket messages themselves (don't rely solely
on cookies). Setting the `SameSite` attribute on cookies to `Lax` or
`Strict` can prevent them from being sent in cross-origin contexts,
which would thwart some CSWSH
attempts[\[26\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=origin%20header%20in%20the%20HTTP,traffic%20in%20the%20victim%E2%80%99s%20browser)[\[29\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=requests%20during%20the%20HTTP%20handshake,equal%20to%20Lax%20or%20Strict).
A detector can check the `Set-Cookie` headers for missing SameSite
attributes as a configuration warning.

In conclusion, WebSockets broaden the attack surface by introducing a
long-lived, bi-directional channel. A multi-protocol attack detector
must treat WebSocket handshake traffic as an extension of HTTP (applying
similar header sanity checks) and treat WebSocket messages as a new
stream to inspect. By doing so, we close the gap that attackers might
otherwise exploit to bypass security measures that stop at the HTTP
layer.

## GraphQL Attack Vectors and Detection

GraphQL is a query language for APIs that allows clients to request
exactly the data they need in a single request. It often operates over
HTTP (typically via `POST` requests with a JSON payload containing the
query, or less commonly via `GET` with the query in the URL). It can
also operate over WebSockets for subscriptions (realtime updates).
GraphQL's flexibility and expressiveness, however, introduce distinctive
security challenges. A multi-protocol attack detector must recognize
GraphQL traffic and monitor for specific abuses. Key attack vectors and
considerations for GraphQL include:

- **Introspection Abuse**: GraphQL has an introspection feature that,
  when enabled, allows a client to query the schema (types, fields,
  mutations available on the server). This is extremely useful for
  development and tooling, but in production it can be risky. If an
  attacker can run an introspection query, they can basically obtain a
  roadmap of the API -- all object types, fields, and possibly even
  comments or deprecated fields that might hint at vulnerabilities.
  Attackers frequently attempt this; in one study, 50% of observed
  GraphQL endpoints were targeted with introspection queries by
  attackers[\[30\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L464%20Based%20on,production%20environments%20unless%20it%E2%80%99s%20necessary).
  The typical introspection query asks for `__schema` or `__type`
  details. For example, an attacker might send:

<!-- -->

- query {
        __schema {
          types { name, fields { name, type { name } } }
        }
      }

  This would dump the entire schema if not blocked. Detection: Our
  detector can catch introspection attempts by looking for the telltale
  `__schema` or `__type` strings in GraphQL requests. Since GraphQL
  queries are often sent as JSON, we need to inspect the request body. A
  WAF like ModSecurity can be configured to treat `application/json`
  bodies and apply regex or substring matches. A simple ModSecurity rule
  might be:

      SecRule REQUEST_BODY "@contains __schema" \
        "id:420001,phase:2,deny,status:403,msg:'GraphQL introspection query detected'"

  This would block any request payload containing "`__schema`".
  Similarly, one could look for the string `"IntrospectionQuery"` (the
  default query name used by GraphiQL and other tools) or even the
  structure of an introspection query. On the Suricata side, one could
  write an IDS rule for the JSON content as well. However, attackers
  have clever variants -- for instance, omitting the double underscore
  (some GraphQL implementations allow querying `schema` without the
  underscores)[\[31\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L434%20We%20observed,prefix%20from%20the%20entire%20query).
  Our detection should account for these variations (e.g.,
  content:`"schema"` preceded by maybe `{` in JSON). Generally, if your
  GraphQL API should not be introspectable by arbitrary clients, any
  introspection attempt is suspect. Best practice is actually to disable
  introspection on production GraphQL endpoints or restrict it to
  authorized
  users[\[30\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L464%20Based%20on,production%20environments%20unless%20it%E2%80%99s%20necessary)[\[32\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=object%20properties%2C%20according%20to%20requester,production%20or%20publicly%20accessible%20environments).
  The detector serves as a safety net to catch any attempt that gets
  through.

<!-- -->

- **GraphiQL and API Explorer Exposure**: GraphiQL is an in-browser IDE
  for exploring GraphQL APIs, usually accessible at an endpoint like
  `/graphiql` or `/graphql-playground`. Leaving these tools enabled in
  production is dangerous -- they often have introspection enabled and
  can help attackers craft queries. Attackers will scan for common
  GraphiQL
  URLs[\[33\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L474%20Just%20like,endpoint%20of%20your%20API).
  A multi-protocol detector can watch HTTP access logs or requests for
  paths containing `graphiql` or `playground` and raise an alert if
  these admin/dev interfaces are being accessed. Simply seeing an HTTP
  200 OK to a `/graphiql` path might warrant a security review of that
  server. Ideally, GraphiQL should be disabled or protected by
  authentication in
  production[\[34\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=control%20validation%2C%20possibly%20using%20some,production%20or%20publicly%20accessible%20environments).
  Our detector thus functions as both an attack detector and a
  configuration monitor in this case.

- **Denial of Service via Expensive Queries**: One of the most notorious
  GraphQL issues is that a client can craft extremely complex or deep
  queries that consume enormous server resources. Because the client
  controls the query structure (including nested relationships,
  filtering, etc.), a malicious query could, for example, request a
  deeply nested data set that causes the server to perform thousands of
  database lookups, or a query with a large number of fields that
  increases response size drastically. An example often cited is a
  **deeply nested query**: imagine a schema with a `friends`
  relationship that allows querying friends-of-friends-of-friends, and
  an attacker queries 10 levels deep. The response could explode
  exponentially, or the server may iterate recursively and use lots of
  CPU[\[35\]](https://graphql.org/learn/security/#:~:text=Depth%20limiting)[\[36\]](https://graphql.org/learn/security/#:~:text=underlying%20data%20sources%2C%20overly%20nested,resources%20and%20impact%20API%20performance).
  Another example is abusing **fragments** (GraphQL fragments can be
  recursive or cyclic if not guarded). Researchers have shown it's
  possible to create a query that references fragments in a cycle, which
  could theoretically cause infinite work on the
  server[\[37\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=Image%3A%20Figure%206%20Introspection%20URLsFigure,an%20escalating%20directive%20overload%20sequence)[\[38\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=This%20is%20similar%20to%20the,a%20maximum%20of%207%20times).
  Many GraphQL servers will detect this and error out, but it's an
  attack to be aware of. There's also the concept of **batching
  attacks**[\[39\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=GraphQL%20supports%20batching%20requests%2C%20also,common%20way%20to%20do%20query)
  -- GraphQL allows sending multiple operations in one request (or using
  aliases to simulate multiple queries), so an attacker can batch 1000
  small queries into one HTTP call, making it harder to detect and
  amplifying the impact (a sort of brute-force via a single request).
  All these are primarily *application-level DoS* attacks. Detection: At
  the network level, one clue might be an extremely large HTTP request
  body or an extremely large response. If we see a GraphQL query
  response of, say, 50MB where typical responses are 100KB, that's a red
  flag (the damage is kind of done, but at least we know). More
  proactively, an IDS/IPS could attempt to parse GraphQL queries and
  enforce a limit on depth or field count. This is complex to do
  externally. However, application-side measures exist: for instance,
  libraries or plugins for GraphQL servers can perform **query
  complexity analysis** and reject overly complex queries before
  execution[\[40\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=)[\[41\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=APIs%20using%20graphql,to%20enforce%20max%20query%20cost).
  Our multi-protocol detector's role is mainly to log such cases and
  possibly use heuristic rules (e.g., if a JSON query contains an object
  depth beyond a threshold or has a huge number of repeated aliases). If
  we integrate closely with the application, we could get metrics like
  execution time or resource usage per query and alert if they exceed
  norms.

- **Injection and Data Exfiltration**: GraphQL endpoints can suffer from
  injection flaws too, but often the injection would target the
  underlying data layer (e.g., NoSQL/SQL injections in resolvers). From
  the protocol perspective, these look like normal queries with perhaps
  odd filter values. Traditional database injection detection (looking
  for `' or 1=1`) could still be relevant if the GraphQL is just passing
  those to a SQL backend. Our WAF rules for SQLi and XSS in HTTP bodies
  will also apply to GraphQL JSON payloads (assuming we parse the JSON
  or at least search the raw text). So, the existing HTTP/1.1 signatures
  for injections can catch obvious malicious inputs within GraphQL.
  However, GraphQL often encourages using query variables (parameters),
  which might not show the malicious payload in the query string itself.
  For example:

<!-- -->

- query getUser($uid: ID!) { user(id: $uid) { name email } }

  with variables `{ "uid": "someValue' OR '1'='1" }`. A naive pattern
  match on the query string wouldn't see the `' OR '1'='1`. But if we
  treat the entire JSON (including variables) as input, our detector can
  catch it. ModSecurity's JSON body parser could help here, allowing
  rules on JSON fields. In summary, general injection detection should
  be extended to GraphQL traffic as well.

To illustrate a simple detection of GraphQL-specific abuse, consider
introspection again. We can use Suricata to detect an introspection
query in flight. If the GraphQL API is accessed over HTTP, Suricata can
match the content in the HTTP POST body:

    # Suricata rule: Alert on GraphQL introspection attempt (detect "__schema" in HTTP POST body)
    alert http any any -> any any (msg:"GraphQL Introspection Query Detected"; flow:to_server; content:"__schema"; http.body; nocase; sid:420003;)

In this rule, `http.body` is the buffer containing the HTTP request
body, which in a GraphQL query would hold the JSON with the query. We
search for the substring `__schema`
case-insensitively[\[42\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=We%20observed%20several%20introspection%20attack,retrieve%20information%20about%20the%20API)[\[30\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L464%20Based%20on,production%20environments%20unless%20it%E2%80%99s%20necessary).
If our GraphQL is over WebSocket (for subscriptions), we could similarly
apply a WebSocket payload rule looking for `__schema`. A real attacker
might obfuscate the query (e.g., use aliases or Unicode escapes), so
perfect detection is hard, but these rules catch the common cases.

Another example: If we want to detect a potential batching attack, we
might look for a GraphQL request containing a very large array (since
batching can be sending an array of many query objects). A rough
heuristic rule could be: "if the request body contains `"[{"` more than,
say, 10 times (which might imply an array of 10 query operations), alert
it." Or if using aliases, look for repeated alias patterns. These would
be custom rules tailored to the API's normal behavior.

It's worth noting that specialized solutions are emerging: some WAFs
have GraphQL awareness -- for instance, vendor tools can parse GraphQL
and apply field-level access control or depth
limiting[\[43\]](https://www.fastly.com/blog/introducing-graphql-inspection-for-the-fastly-next-gen-waf#:~:text=Introducing%20GraphQL%20Inspection%20for%20the,and%20other%20vulnerabilities%20that)[\[44\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=,to%20return%20more%20or%20fewer).
Our multi-protocol detector can integrate such logic or at least not
blind itself to GraphQL (treating it as just JSON API traffic to
monitor).

**Defense in depth for GraphQL** is crucial. From the application side,
recommended practices include disabling introspection and GraphiQL in
production, implementing depth limits (max query depth), breadth limits
(max number of top-level query fields or aliases), and complexity
scoring (assign a cost to each field and reject queries exceeding a
threshold)[\[45\]](https://graphql.org/learn/security/#:~:text=One%20of%20GraphQL%E2%80%99s%20strengths%20is,selection%20set%20are%20deeply%20nested)[\[40\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=).
Rate limiting queries per client/IP is also
important[\[46\]](https://graphql.org/learn/security/#:~:text=,36)[\[47\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=).
While these are preventive measures, our detector plays the role of
identifying when these limits are being probed or breached. For example,
if introspection is *supposedly* off but our IDS still sees an
introspection response, we know something's wrong. Or if an attacker is
trying a known bypass (like the `__schema` vs `schema`
trick[\[31\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L434%20We%20observed,prefix%20from%20the%20entire%20query)),
the detector can catch it even if the server might allow it.

To summarize, GraphQL adds an API layer that needs its own monitoring.
The multi-protocol attack detector watches GraphQL queries on the
network just like it would SQL statements or REST calls -- looking for
signs of misuse such as introspection queries, abnormally large or
complex requests, and any known bad patterns. By doing so, it helps
ensure that the flexibility of GraphQL doesn't become a blind spot for
security.

## Conclusion

The **Multi-Protocol Attack Vector Detector** approach acknowledges that
modern applications no longer communicate over a single protocol, and
thus security monitoring must extend across HTTP/1.1, HTTP/2,
WebSockets, GraphQL, and beyond. Each layer -- whether it's a transport
enhancement like HTTP/2 or an application abstraction like GraphQL --
can introduce new attack surfaces. Attackers will continuously repurpose
old vulnerabilities on new protocols (for instance, HTTP request
smuggling reappearing via HTTP/2 translators, or resource exhaustion
attacks via GraphQL queries). It is therefore critical for organizations
to have an agile and layered response to emerging
threats[\[48\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=HTTP%20Request%20Smuggling%20seems%20to,and%20identify%20any%20new%20issues).

By deploying both network-based detection (IDS) and host-based
protections (WAF with relevant rulesets) in concert, we can cover these
bases. Suricata gives us visibility into the lower-level protocol
nuances (frames, handshake oddities, etc.), while ModSecurity/CRS can
enforce application-level sanity (blocking known malicious payloads).
Throughout this report, we preserved the content and configuration
examples from the original technical analysis -- including rule samples
and settings -- now formatted in Markdown for clarity and reference. All
sections, from HTTP/1.1 to GraphQL, demonstrate how a comprehensive
detector operates: **protocol awareness** (knowing how to
parse/interpret each protocol), **signature and behavior analysis**
(leveraging known bad patterns and heuristic anomaly detection), and
**cross-protocol correlation** (understanding interactions, like an
HTTP/2 request leading to an HTTP/1.1 attack, or a GraphQL query
traveling over a WebSocket).

In practice, implementing a multi-protocol detector means continuously
updating your rules and tools as new protocol features and attacks are
discovered. For example, HTTP/3 (which operates over QUIC) is the next
frontier -- we can expect similar scrutiny to ensure its adoption
doesn't open new holes. The good news is that the principles laid out
here will extend: careful validation of protocol use, reuse of existing
security knowledge on new platforms, and broad visibility. With the
strategies discussed, defenders can significantly harden their systems
against multi-vector, multi-protocol attacks, ensuring that no matter
how an attacker tries to slip in -- through a classic HTTP request or a
stealthy WebSocket frame -- the attempt will be observed and mitigated.
