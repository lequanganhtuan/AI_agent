# 🛡️ Enterprise AI URL Safety & Fraud Detection Platform

Welcome to the **Enterprise AI URL Safety & Fraud Detection Platform**—a modular, asynchronous, multi-phase threat assessment pipeline designed to inspect, validate, analyze, and neutralize malicious URLs. 

By combining **static lexical heuristics**, **brand-spoofing detection**, **multi-provider Threat Intelligence (Threat Intel) aggregation**, and **sandboxed dynamic browser execution**, this platform offers a deep, 360-degree security assessment of any incoming URL or domain.

---

## 🚀 Key Capabilities

*   **Asynchronous Processing**: Powered by Python's `asyncio` to execute intensive external APIs and sandboxed browser navigations concurrently, achieving low-latency verdicts.
*   **Decoupled Multi-Phase Architecture**: Separates parsing, static features, external threat databases, and live page behavior into highly customizable, independent layers.
*   **Resilient Threat Intel Orchestrator**: Queries multiple industry-standard security APIs (VirusTotal, Google Safe Browsing, PhishTank, URLhaus, AbuseIPDB, URLScan) in parallel with automatic timeouts, error isolation, and caching.
*   **Headless Dynamic Analysis**: Spawns an automated Playwright chromium instance to capture redirect chains, sniff network traffic, audit DOM inputs (for credential harvesting/OTP forms), execute script telemetry, and capture screenshot evidence.
*   **Interactive Analytics Dashboard**: Provides a sleek, dark-mode Web UI showing live metrics, scoring breakdown, redirect timelines, DOM telemetry, and page screenshots.

---

## 📂 Project Directory Structure

```directory
AI_agent/
├── .env                       # Environment configurations (API keys & endpoints)
├── .gitignore                 # Specifies intentionally untracked files
├── requirements.txt           # Python application dependencies
├── run_dynamic_scenarios.py   # Executable script simulating live dynamic crawls
├── test.ipynb                 # Interactive Jupyter notebook for prototyping
├── artifacts/                 # Saved execution assets (e.g., screenshots, logs)
│   └── scenarios_screenshots/
├── src/                       # Primary Source Code Directory
│   ├── app.py                 # FastAPI Web Application & API Gateway
│   ├── core/                  # Core Models, Settings, and Exceptions
│   │   ├── enums.py           # Common enums (e.g. Risk levels)
│   │   ├── exceptions.py      # Base application errors
│   │   ├── models.py          # Unified Pydantic schema declarations
│   │   └── settings.py        # Pydantic Settings Manager (loads .env)
│   ├── dns/                   # Custom DNS Resolution Modules
│   │   ├── cache.py           # TTL-respecting DNS query cache
│   │   ├── resolver.py        # Secure DNS client
│   │   └── dnspython_resolver.py
│   ├── analyzers/             # Deep URL Inspection Analyzers
│   │   ├── base.py            # Base Analyzer interface
│   │   └── url/               # Specialized URL Analysis components
│   │       ├── preprocessing/ # Normalization & validation checks
│   │       ├── static/        # Lexical heuristics, brand & typosquatting detection
│   │       ├── threat_intelligence/ # 3rd-party Threat Intel integrations
│   │       └── dynamic_analysis/    # Headless Playwright browser sandbox
│   └── static/                # Web Dashboard Static Assets
│       ├── index.html         # Dashboard template
│       ├── style.css          # Sleek glassmorphism styled layout
│       └── script.js          # Interactive frontend rendering & request loop
└── tests/                     # Unit & Integration Test Suites
    ├── data/                  # Static test fixtures
    ├── unit/                  # Modular unit tests (Static, DNS, Preprocessing)
    ├── integration/           # Multi-component pipeline tests
    └── run_scenarios.py       # Phase 3 Threat Intel logic validator
```

---

## 🔄 The 5-Phase Analysis Pipeline

The system processes every URL through five progressive validation and detection phases:

```mermaid
flowchart TD
    subgraph P1[Phase 1: Preprocessing & DNS Validation]
        A["Input URL"] --> B["validator.py<br>Validation"]
        B -- Invalid --> Err["HTTP 400 Error"]
        B -- Valid --> C["normalizer.py<br>Normalization"]
        C --> D["tldextract<br>Component Parsing"]
        D --> E["resolver.py<br>DNS Resolution"]
        E --> E_Cache["cache.py<br>DNS Cache Check"]
        E_Cache -- Hit --> F["Validation Result"]
        E_Cache -- Miss --> DNS_Query["Network DNS Query"] --> Cache_Save["Save DNS Cache"] --> F
    end

    subgraph P2[Phase 2: Static Heuristics & Lexical Analysis]
        F --> G["static_url_analyzer.py"]
        G --> H1["lexical_analyzer.py<br>Entropy & Lengths"]
        G --> H2["brand_analyzer.py<br>Brand Imitation"]
        G --> H3["typosquatting_analyzer.py<br>Levenshtein Check"]
        G --> H4["pattern_analyzer.py<br>Suspicious Keyword Patterns"]
        G --> H5["tld_analyzer.py<br>High-Risk Registry Check"]
        H1 & H2 & H3 & H4 & H5 --> I["static_risk_calculator.py"]
        I --> J["Static Risk Score"]
    end

    subgraph P3[Phase 3: Parallel Threat Intelligence]
        F --> K["orchestrator.py"]
        K --> L_Cache["Redis Cache Check"]
        L_Cache -- Hit --> M["Threat Intel Result"]
        L_Cache -- Miss --> API_Lookup["Concurrent API Lookup"]
        subgraph API_Providers[Third-Party Security Providers]
            API_Lookup --> VT["VirusTotal"]
            API_Lookup --> GSB["Google Safe Browsing"]
            API_Lookup --> PT["PhishTank"]
            API_Lookup --> UH["URLhaus"]
            API_Lookup --> AB["AbuseIPDB"]
            API_Lookup --> US["URLScan"]
        end
        VT & GSB & PT & UH & AB & US --> N["Aggregator &<br>Timeout Fallback"]
        N --> Cache_Store["Store in Redis"] --> M
    end

    subgraph P4[Phase 4: Sandboxed Dynamic Analysis]
        F --> O["dynamic_analysis/orchestrator.py"]
        O --> P["browser_engine.py<br>Playwright Launch"]
        P --> Q["network_analyzer.py<br>Start Traffic Capture"]
        Q --> R["page_loader.py<br>Navigation & Load"]
        R --> S["screenshot_collector.py<br>Full-Page Capture"]
        R --> T["Post-Load Analysis"]
        subgraph Evaluation[Evaluation Engines]
            T --> T1["redirect_analyzer.py<br>Chains & Loops"]
            T --> T2["dom_analyzer.py<br>Forms, Hidden Iframes, script tags"]
            T --> T3["network_analyzer.py<br>APIs, WebSockets, CDNs"]
        end
        S & T1 & T2 & T3 --> U["risk & summary<br>Calculators"]
        U --> V["Dynamic Risk Result"]
    end

    subgraph P5[Phase 5: Output & Dashboard Visualization]
        J & M & V --> W["FastAPI app.py<br>AnalysisContext Composer"]
        W --> X["Web UI Dashboard"]
        X --> Y1["Interactive Tab Metrics"]
        X --> Y2["Screenshot Preview"]
        X --> Y3["Timeline Visualization"]
    end
```

### Phase 1: Preprocessing & DNS Validation
*   **Validation**: Asserts URL structure, extracts parameters, and intercepts private IPs or invalid formats before executing outbound queries.
*   **Normalization**: Corrects casing, trims whitespace, standardizes query parameters, and handles Punycode internationalized domains to establish a deterministic cache key.
*   **DNS Resolution**: Checks actual domain viability via a custom resolver featuring a thread-safe, TTL-sensitive caching system.

### Phase 2: Static Heuristics & Lexical Analysis
Checks properties of the URL itself without making network calls to external sites:
*   **Lexical Features**: Computes entropy, digit ratios, depth, token lengths, and special characters.
*   **Brand Spoofing**: Compares the target domain against lists of high-traffic brands to identify phishing targets.
*   **Typosquatting/Combosquatting**: Applies Levenshtein distance metrics to catch lookalike domains (e.g., `g00gle.com`, `paypal-security-update.net`).
*   **TLD Check**: Matches top-level domains against list of high-risk spam or malware registrars.
*   **Static Risk Score**: Computes a rules-based static risk score from these local signals.

![Static Heuristics Analysis](artifacts/phase2_static.png)

### Phase 3: Parallel Threat Intelligence
Aggregates live reputation data from multiple providers concurrently:
*   **VirusTotal**: Checks detection engines and file-reputation counts.
*   **Google Safe Browsing**: Flags malware, phishing, and social engineering hazards.
*   **AbuseIPDB**: Assesses host IP reputation, reports count, and hosting metadata.
*   **URLhaus**: Queries active malware payload distribution lists.
*   **URLScan**: Identifies behavioral and site-level hazards.
*   **Error Tolerance**: If a single API provider experiences network timeouts or quota exhaustion, it is gracefully isolated. The engine continues processing and adjusts the overall **Confidence Score** proportional to the succeeded lookups.

![Threat Intelligence Analysis](artifacts/phase3_threat.png)

### Phase 4: Sandboxed Dynamic Browser Crawling
A live headless crawler visits the site inside a secure Playwright environment:
*   **Redirect Chains**: Captures all HTTP and meta-refresh redirects, tracking cross-domain jumps and loops.
*   **DOM Auditing**: Scans for hidden iframes, JavaScript obfuscation tags (such as excessive `eval()`, `atob()`, or `unescape()`), and forms gathering sensitive fields (e.g. Passwords, OTPs, Identity Cards, Credit Cards).
*   **Network Sniffing**: Inspects API endpoints, WebSocket activities, and CDN connections during loading.
*   **Visual Evidence**: Captures full-page screenshots for security operators to audit.

![Dynamic Sandbox Analysis](artifacts/phase4_dynamic.png)

### Phase 5: Web UI Dashboard
A rich dashboard displays the results:
*   **Interactive Tabs**: Separate tabs for **Static**, **Threat Intel**, and **Dynamic** logs.
*   **Risk Metrics**: Animated circular gauge rendering consolidated risk ratings (Clean, Suspicious, Malicious).
*   **Visual Timeline**: Interactive redirection path timeline detailing jump status, latency, and apex domains.
*   **Screenshot Preview**: Embedded preview pane displaying full-page visual evidence.

---

## 🛠️ Installation & Setup

### Prerequisites
*   Python 3.10+
*   Node.js (for Playwright system dependencies, optional but recommended)
*   Redis server (optional, for Phase 3/4 caching)

### 1. Clone & Setup Virtual Environment
```bash
git clone <repository-url>
cd AI_agent
python -m venv venv
venv\Scripts\activate      # Windows
# or: source venv/bin/activate  # macOS/Linux
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
playwright install chromium
```

### 3. Configure Environment Variables
Create a `.env` file in the root directory. Fill in your API keys (you can request developer keys from the providers' websites):
```ini
ENVIRONMENT=development
DEBUG=True

# Third-Party APIs
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here
URLHAUS_API_KEY=your_urlhaus_api_key_here
ABUSEIPDB_API_KEY=your_abuse_ip_db_api_key_here

# Optional Configurations
# REDIS_URL=redis://localhost:6379/0
# DATABASE_URL=postgresql://user:pass@localhost:5421/db
```

---

## 🎮 Running the Platform

### Running the Web Application
Launch the FastAPI server:
```bash
uvicorn src.app:app --reload --host 127.0.0.1 --port 8000
```
Open your browser and navigate to `http://127.0.0.1:8000`.

### Running Dynamic Scenario Crawler (Terminal)
To run automated crawling scenarios directly from the CLI:
```bash
python run_dynamic_scenarios.py
```
This runs 11 different test URLs (Google, Github login flow, TinyURL redirect, active websocket connections, faulty paths, private IPs, etc.) and exports screenshot evidence into `artifacts/scenarios_screenshots/`.

---

## 🧪 Simulation Harness & Scenarios

To help test the scoring engine and pipeline robustness, the Web App features mock scenario interception when inputting testing URLs:

| Scenario | Trigger URL pattern | Description | Expected Risk & Signals |
| :--- | :--- | :--- | :--- |
| **Scenario 1** | `*scenario1*.test` | Completely clean website mockup. | `LOW` Risk, 0 score. |
| **Scenario 2** | `*scenario2*.test` | Blacklist detection simulator. | `MEDIUM` Risk, triggers `GOOGLE_BLACKLIST` & `VT_CONFIRMED_MALICIOUS`. |
| **Scenario 3** | `*scenario3*.test` | Behavioral credential harvest simulation. | `MEDIUM` Risk, triggers `PHISHING_FORM_DETECTED`. |
| **Scenario 4** | `*scenario4*.test` | Malicious IP/Proxy reputation simulator. | `MEDIUM` Risk, triggers `ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS`. |
| **Scenario 5** | `*scenario5*.test` | API provider timeout / failure handling. | `LOW` Risk, confidence score drops to `0.8`. |
| **Scenario 6** | `*scenario6*.test` | Cache Hit simulation. | `MEDIUM` Risk, instant payload return. |
| **Scenario 7** | `*scenario7*.test` | All threat buckets compounded. | `HIGH` Risk, maximum composite score of `80`. |

To run the pipeline verification scenario unit tests:
```bash
pytest tests/run_scenarios.py
```

---

## 🛡️ Security & Sandboxing Considerations

> [!WARNING]
> Dynamic analysis crawls live URLs. Crawling active threat vectors could trigger drive-by downloads or browser-level exploits.
> *   Ensure the host executing dynamic crawls resides in an isolated network segment (DMZ/VPC).
> *   Do not disable Playwright's `NO_SANDBOX` flag in production environments.
> *   Use API token rate-limiting to prevent exceeding quota thresholds on provider platforms.
