# Prompts for gemini-fast
**Role:** You are acting as a Senior Cybersecurity Researcher and Network Security Architect.

**Objective:** Conduct an in-depth technical analysis and prepare a comprehensive Markdown report for a system titled "Multi-Protocol Attack Vector Detector." This system aims to detect threats across diverse communication protocols beyond standard HTTP.

**Scope of Work:**
Research and analyze the following protocols and attack vectors:
- **WebSockets (WS/WSS):** Detecting XSS, data manipulation, and session hijacking via socket connections.
- **GraphQL:** Identifying Query Complexity Attacks (DoS), deep nesting issues, and unauthorized data access.
- **SQL Injection:** Detecting classic and advanced SQLi payloads in various data streams.
- **HTTP/1.1 & HTTP/2:** Analyzing anomalous HTTP methods, malformed headers, and Request Smuggling.

**Required Report Structure:**
Please provide the response as a detailed Markdown report covering the following five points:

1. **Core Working Principles:** Explain the fundamental mechanisms of these protocols (WS, HTTP/2, GraphQL) and how they can be monitored or intercepted for threat detection.
2. **Best Practices & Industry Standards:** Detail the security benchmarks and industry standards (e.g., OWASP, NIST, RFCs) relevant to these technologies.
3. **Open-Source Landscape & Competitors:** List similar open-source projects, IDS/IPS tools, or commercial solutions that focus on multi-protocol security (e.g., Snort, Suricata, Zeek, or specialized WAFs).
4. **Critical Configuration Parameters:** Identify essential configuration files, environment variables, and threshold settings necessary for an effective detection engine.
5. **Critical Security Considerations:** Highlight high-risk vulnerabilities and provide advice on mitigating false positives/negatives during multi-protocol analysis.

**Output Format:**
- Use clear headings and subheadings.
- Use tables for technical comparisons where appropriate.
- Provide credible references, official documentation links, or whitepapers for each section.
