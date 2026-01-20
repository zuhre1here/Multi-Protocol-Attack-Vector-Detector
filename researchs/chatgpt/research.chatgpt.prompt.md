# Prompts for chatgpt
# GOAL
I want to design and research a **Multi-Protocol Attack Vector Detector** — a comprehensive security analysis system capable of detecting attack vectors not only over HTTP, but across multiple communication protocols.

# CONTEXT
Modern applications increasingly rely on multiple protocols (HTTP, WebSockets, GraphQL, etc.), which expands the attack surface beyond traditional web requests. The goal is to understand how attacks manifest across these protocols and how they can be detected effectively.

# SCOPE
## Protocol Coverage
- HTTP/1.1 and HTTP/2
- WebSockets (WS / WSS)
- GraphQL over HTTP and WebSockets

## Attack Types to Detect
- **WebSockets**
  - XSS payloads transmitted over socket messages
  - Data manipulation and protocol abuse
- **GraphQL**
  - Query complexity attacks (depth, cost-based abuse)
  - Unauthorized data access attempts
  - Introspection abuse
- **SQL Injection**
  - Classical and modern SQL injection payloads
- **HTTP Requests**
  - Abnormal or non-standard HTTP methods
  - Malicious or suspicious HTTP headers
  - Protocol misuse patterns

# TECHNICAL QUESTIONS TO ANSWER
1. What are the fundamental working principles of each protocol (HTTP, HTTP/2, WebSockets, GraphQL)?
2. What are the industry best practices and security standards for protecting these protocols?
3. What open-source projects, tools, or competing solutions exist for multi-protocol attack detection?
4. What are the critical configuration files, parameters, and tuning options involved in securing or monitoring these protocols?
5. What are the most critical security pitfalls and attack vectors to watch for when operating such systems?

# DELIVERABLE
- **Format:** Detailed technical Markdown report
- **Structure:**
  - Executive Summary
  - Protocol Fundamentals
  - Attack Vector Analysis per Protocol
  - Best Practices & Industry Standards
  - Open-Source Tools & Competitor Analysis
  - Configuration & Tuning Guidelines
  - Security Risks & Mitigation Strategies
- **Depth:** Advanced / security-research level
- **Sources:** Cite authoritative references such as OWASP, NIST, RFCs, official protocol documentation, and reputable security research papers.

Please provide **well-cited sources** and technical depth suitable for a cybersecurity professional or security engineer.

Deployment Context: Hybrid environment combining cloud-native Kubernetes workloads and on-premises infrastructure.

Traffic Capture: Both real-time (live) traffic inspection and offline log-based analysis.

Language Preferences: Go and Rust as primary languages for high-performance detection components, with Python for prototyping and analysis.

Integration Targets: Kubernetes, Envoy Proxy, NGINX, Suricata, and Zeek.
