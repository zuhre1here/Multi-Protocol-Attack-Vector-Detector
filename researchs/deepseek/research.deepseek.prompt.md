# Prompts for deepseek
**System:** Multi-Protocol Attack Vector Detector  
**Objective:** To conduct an in-depth technical analysis for a comprehensive system designed to detect attack vectors across diverse communication protocols, not limited to standard HTTP.

**Required Protocol & Threat Coverage:**
*   **WebSockets (WS/WSS):** Capable of capturing XSS, data manipulation, and session hijacking attempts over socket connections.
*   **GraphQL:** Able to detect Query Complexity Attacks (DoS), deep nesting issues, and unauthorized data access attempts within GraphQL queries.
*   **SQL Injection:** Must identify classic and advanced SQLi payloads within various data streams.
*   **HTTP/1.1 & HTTP/2:** Must analyze anomalous HTTP methods, malformed headers, and techniques like HTTP Request Smuggling.

**Scope of Technical Research:**
Provide a detailed technical investigation covering the following five points for the protocols in scope (WS/WSS, HTTP/1.1/2, GraphQL):
1.  **Core Working Principles:** What are the fundamental mechanisms of these technologies, and how can they be monitored or intercepted for threat detection?
2.  **Best Practices & Industry Standards:** What are the security benchmarks, RFCs, and standards (e.g., OWASP, NIST) relevant to securing these protocols?
3.  **Open-Source Landscape & Competitors:** What similar open-source projects, IDS/IPS tools (e.g., Snort, Suricata, Zeek), or commercial solutions exist?
4.  **Critical Configuration Parameters:** What are the essential configuration files, environment variables, and threshold settings for an effective detection engine?
5.  **Critical Security Considerations:** What are the high-risk vulnerabilities, and what advice mitigates false positives/negatives in multi-protocol analysis?

**Output Format:** Please deliver the analysis as a comprehensive, well-structured Markdown report with clear headings, technical comparison tables where appropriate, and credible references or official documentation links for each section.
