# Sources for chatgpt
**Sources:** The content above was drawn from a synthesis of the
original technical report and various references (citations inline) on
HTTP/2
vulnerabilities[\[1\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=research%20focuses%20on%20the%20fact,be%20created%20and%20cause%20a)[\[10\]](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/#:~:text=This%20attack%20was%20made%20possible,facing%20web%20or%20API%20server),
WebSocket security
research[\[22\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=does%20leave%20the%20Origin%20header,most%20developers%20are%20unaware%20of)[\[25\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=The%20HTML%20snippet%20below%20shows,this%20would%20be%20a%20finding),
GraphQL threat
analysis[\[30\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L464%20Based%20on,production%20environments%20unless%20it%E2%80%99s%20necessary)[\[45\]](https://graphql.org/learn/security/#:~:text=One%20of%20GraphQL%E2%80%99s%20strengths%20is,selection%20set%20are%20deeply%20nested),
and official documentation for Suricata and
ModSecurity[\[13\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=alert%20http%20%24HOME_NET%20any%20,authority%3A%20example.com)[\[3\]](https://owasp.org/www-project-modsecurity/#:~:text=The%20OWASP%20ModSecurity%20project%20provides,brings%20protection%20against%20HTTP%20attacks).
All citations have been preserved per the original report, and
configuration/code examples remain intact, now presented in Markdown
format for ease of reading.

[\[1\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=research%20focuses%20on%20the%20fact,be%20created%20and%20cause%20a)
[\[4\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=Akamai%20responded%20to%20the%20original,HTTP%20Request%20Smuggling%20such%20as)
[\[6\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=concept%20tooling%20from%20CERT%2FCC%20,The%20http2smugl)
[\[7\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=Error%3A%20server%20dropped%20connection%2C%20error%3Derror,code%20PROTOCOL_ERROR)
[\[17\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=wide%20variety%20of%20web%20clients,then%20forwarded%20to%20the%20origin)
[\[48\]](https://www.akamai.com/blog/security/http-2-request-smulggling#:~:text=HTTP%20Request%20Smuggling%20seems%20to,and%20identify%20any%20new%20issues)
Akamai Blog \| HTTP/2 Request Smuggling

<https://www.akamai.com/blog/security/http-2-request-smulggling>

[\[2\]](https://graphql.org/learn/security/#:~:text=On%20this%20page%2C%20we%E2%80%99ll%20survey,GraphQL%20API%20from%20malicious%20operations)
[\[35\]](https://graphql.org/learn/security/#:~:text=Depth%20limiting)
[\[36\]](https://graphql.org/learn/security/#:~:text=underlying%20data%20sources%2C%20overly%20nested,resources%20and%20impact%20API%20performance)
[\[45\]](https://graphql.org/learn/security/#:~:text=One%20of%20GraphQL%E2%80%99s%20strengths%20is,selection%20set%20are%20deeply%20nested)
[\[46\]](https://graphql.org/learn/security/#:~:text=,36) Security \|
GraphQL

<https://graphql.org/learn/security/>

[\[3\]](https://owasp.org/www-project-modsecurity/#:~:text=The%20OWASP%20ModSecurity%20project%20provides,brings%20protection%20against%20HTTP%20attacks)
OWASP ModSecurity \| OWASP Foundation

<https://owasp.org/www-project-modsecurity/>

[\[5\]](https://nikhil-c.medium.com/suricata-creating-rules-with-practical-scenarios-df659e87d515#:~:text=%2A%20Metasploit%20Cross,payloads%20or%20script%20injection%20patterns)
Suricata : Creating Rules with practical scenarios \| by Nikhil
Chaudhari \| Medium

<https://nikhil-c.medium.com/suricata-creating-rules-with-practical-scenarios-df659e87d515>

[\[8\]](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487#:~:text=The%20vulnerability%20%28CVE,August%202023%20through%20October%202023)
HTTP/2 Rapid Reset Vulnerability, CVE-2023-44487 \| CISA

<https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487>

[\[9\]](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/#:~:text=Starting%20on%20Aug%2025%2C%202023%2C,previous%20biggest%20attack%20on%20record)
[\[10\]](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/#:~:text=This%20attack%20was%20made%20possible,facing%20web%20or%20API%20server)
HTTP/2 Rapid Reset: deconstructing the record-breaking attack

<https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/>

[\[11\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=was%20surprised%20that%20Suricata%20did,have%20the%20HTTP%2F2%20parsing%20disabled)
[\[12\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=version%206,enable%20HTTP%2F2%20logging%20and%20alerting)
[\[13\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=alert%20http%20%24HOME_NET%20any%20,authority%3A%20example.com)
[\[14\]](https://community.emergingthreats.net/t/http-2-in-suricata-6/257#:~:text=With%20overloading%20enabled%20via%20the,covered%20by%20a%20single%20rule)
HTTP/2 in Suricata 6 - Tutorials, Tips & Tricks - Emerging Threats

<https://community.emergingthreats.net/t/http-2-in-suricata-6/257>

[\[15\]](https://docs.suricata.io/en/latest/rules/http2-keywords.html#:~:text=Match%20on%20the%20frame%20type,present%20in%20a%20transaction)
[\[16\]](https://docs.suricata.io/en/latest/rules/http2-keywords.html#:~:text=http2.settings%3ASETTINGS_ENABLE_PUSH%3D0%3B%20http2.settings%3ASETTINGS_HEADER_TABLE_SIZE)
8.35. HTTP2 Keywords --- Suricata 9.0.0-dev documentation

<https://docs.suricata.io/en/latest/rules/http2-keywords.html>

[\[18\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=The%20WebSocket%20Protocol%2C%20standardized%20in,time%20events)
[\[19\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=The%20differences%20between%20the%20traditional,terminated%2C%20requiring%20a%20new%20request)
[\[20\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=certain%20sites%20SHOULD%20verify%20the,HTTP%20403%20Forbidden%20status%20code)
[\[21\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=match%20at%20L183%20does%20leave,most%20developers%20are%20unaware%20of)
[\[22\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=does%20leave%20the%20Origin%20header,most%20developers%20are%20unaware%20of)
[\[23\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=match%20at%20L203%20origin%20header,traffic%20in%20the%20victim%E2%80%99s%20browser)
[\[24\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=This%20blog%20will%20demonstrate%20how,io)
[\[25\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=The%20HTML%20snippet%20below%20shows,this%20would%20be%20a%20finding)
[\[26\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=origin%20header%20in%20the%20HTTP,traffic%20in%20the%20victim%E2%80%99s%20browser)
[\[29\]](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/#:~:text=requests%20during%20the%20HTTP%20handshake,equal%20to%20Lax%20or%20Strict)
Can\'t Stop, Won't Stop Hijacking (CSWSH) WebSockets  - Black Hills
Information Security, Inc.

<https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/>

[\[27\]](https://docs.suricata.io/en/latest/rules/websocket-keywords.html#:~:text=8)
[\[28\]](https://docs.suricata.io/en/latest/rules/websocket-keywords.html#:~:text=8)
8.39. WebSocket Keywords --- Suricata 9.0.0-dev documentation

<https://docs.suricata.io/en/latest/rules/websocket-keywords.html>

[\[30\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L464%20Based%20on,production%20environments%20unless%20it%E2%80%99s%20necessary)
[\[31\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L434%20We%20observed,prefix%20from%20the%20entire%20query)
[\[33\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=match%20at%20L474%20Just%20like,endpoint%20of%20your%20API)
[\[37\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=Image%3A%20Figure%206%20Introspection%20URLsFigure,an%20escalating%20directive%20overload%20sequence)
[\[38\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=This%20is%20similar%20to%20the,a%20maximum%20of%207%20times)
[\[42\]](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/#:~:text=We%20observed%20several%20introspection%20attack,retrieve%20information%20about%20the%20API)
GraphQL Vulnerabilities and Common Attacks: Seen in the Wild \| Imperva

<https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/>

[\[32\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=object%20properties%2C%20according%20to%20requester,production%20or%20publicly%20accessible%20environments)
[\[34\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=control%20validation%2C%20possibly%20using%20some,production%20or%20publicly%20accessible%20environments)
[\[39\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=GraphQL%20supports%20batching%20requests%2C%20also,common%20way%20to%20do%20query)
[\[40\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=)
[\[41\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=APIs%20using%20graphql,to%20enforce%20max%20query%20cost)
[\[44\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=,to%20return%20more%20or%20fewer)
[\[47\]](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#:~:text=)
GraphQL - OWASP Cheat Sheet Series

<https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

[\[43\]](https://www.fastly.com/blog/introducing-graphql-inspection-for-the-fastly-next-gen-waf#:~:text=Introducing%20GraphQL%20Inspection%20for%20the,and%20other%20vulnerabilities%20that)
Introducing GraphQL Inspection for the Fastly Next-Gen WAF

<https://www.fastly.com/blog/introducing-graphql-inspection-for-the-fastly-next-gen-waf>
