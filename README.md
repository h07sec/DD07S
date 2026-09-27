# IntelligentDDoS

**Intelligent and controlled DDoS simulation framework for authorized security testing and web application resilience assessments.**

> ⚠️ **IMPORTANT — AUTHORIZED USE ONLY**
>
> IntelligentDDoS is designed for controlled security testing, load testing, and resilience assessment of systems you own or have explicit permission to test.
>
> **Do not use this tool against public, third-party, or unauthorized infrastructure.**

---

## Overview

**IntelligentDDoS** is a Python-based web stress-testing and DDoS simulation framework designed to help security engineers evaluate how web applications and infrastructure respond to different types of high-load HTTP traffic.

The tool combines automated target fingerprinting, endpoint discovery, traffic-generation techniques, and an adaptive controller that dynamically allocates testing traffic based on observed server behavior.

The original implementation provides HTTP/1.1 and HTTP/2 testing capabilities, a local web dashboard, CLI operation, endpoint analysis, and authorization interlocks.

---

## Features

### 🔎 Target Fingerprinting

IntelligentDDoS can inspect a target and identify information such as:

* Web server
* Framework indicators
* HTTP version
* WAF indicators
* CDN indicators
* Relevant HTTP response headers
* Basic target behavior

The implementation includes signatures for services such as Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, ModSecurity, and F5.

---

### 🎯 Endpoint Discovery & Ranking

The tool can discover potentially expensive application endpoints using:

* `robots.txt`
* HTML links
* HTML forms
* Script/resource references
* Candidate paths
* Response latency
* Cache-busting requests
* Dynamic-response checks

Discovered endpoints are measured and ranked using an amplification/impact score.

---

## Traffic Simulation Vectors

### HTTP/1.1

The framework includes several controlled HTTP/1.1 stress-testing techniques:

* Cache-busting GET requests
* POST request flooding
* Slowloris-style connections
* Slow-read connections

These are intended for controlled resilience testing of systems where authorization has been obtained.

### HTTP/2

HTTP/2 testing includes:

* HEADERS request flooding
* HTTP/2 Rapid Reset-style testing

The implementation references the HTTP/2 Rapid Reset vulnerability **CVE-2023-44487**.

---

## 🧠 Intelligent Traffic Controller

One of the main components of IntelligentDDoS is its adaptive controller.

Instead of using a completely fixed distribution of traffic, the controller evaluates observed server behavior and adjusts the testing budget between available vectors.

It considers measurements including:

* Average latency
* HTTP 5xx responses
* Request errors
* HTTP 429 responses
* Overall impact

The controller then adjusts vector allocation based on the observed results.

This makes the framework useful for studying questions such as:

> **"How does the application behave as different types of traffic increase?"**

rather than simply generating a fixed amount of traffic.

---

## 📊 Monitoring

IntelligentDDoS tracks testing statistics including:

* Total requests
* Errors
* Timeouts
* Connection failures
* HTTP status codes
* Average latency

These measurements can be used to understand how the target behaves under controlled load.

---

## 🖥️ Web Dashboard

The framework includes a local web interface for controlling and monitoring tests.

The dashboard runs on:

```text
127.0.0.1:8080
```

The interface provides controls for items such as:

* Target
* Test duration
* Request rate
* Socket configuration
* HTTP/2 connections
* Testing vectors
* Current status
* Logs
* Start/stop controls

The interface is intentionally bound to localhost.

---

## 💻 CLI Mode

IntelligentDDoS can also be operated directly from the command line.

Example:

```bash
python3 intelligent_ddos.py cli --target https://staging.local --duration 120
```

> Replace the target with a system you own or have explicit authorization to test.

---

## 🩺 Diagnostic Mode

The project also provides a diagnostic command:

```bash
python3 intelligent_ddos.py doctor
```

This can be used to check the local environment and dependencies before running a test.

---

## 🔐 Safety Controls

IntelligentDDoS contains explicit authorization mechanisms.

The implementation includes:

* Target authorization verification
* `.authorized_target`
* Hard request-rate limitation
* Explicit confirmation when an authorization file does not already exist

The hard-coded maximum rate in the current implementation is **5000 requests per second**.

Before testing an unrecognized target, the CLI requires the operator to verify authorization and records the target hostname through the authorization mechanism.

---

## 📁 Project Structure

A typical project layout:

```text
IntelligentDDoS/
│
├── intelligent_ddos.py
├── .authorized_target
├── README.md
└── LICENSE
```

---

## ⚙️ Requirements

* Python **3.9+**
* Linux, macOS, or Windows environment capable of running the required Python networking libraries
* Internet/network access to the authorized test environment

The application uses:

```text
aiohttp
httpx[http2]
h2
```

The original implementation also includes dependency installation logic for missing packages.

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/IntelligentDDoS.git
cd IntelligentDDoS
```

Install the dependencies:

```bash
pip install aiohttp "httpx[http2]" h2
```

Or allow the application's dependency handling to install missing packages.

---

## ▶️ Usage

### Launch the dashboard

```bash
python3 intelligent_ddos.py ui
```

Then open:

```text
http://127.0.0.1:8080
```

### CLI

```bash
python3 intelligent_ddos.py cli \
    --target https://staging.local \
    --duration 120
```

### Diagnostics

```bash
python3 intelligent_ddos.py doctor
```

---

## 🧪 Recommended Testing Workflow

For an authorized security assessment:

```text
        ┌──────────────────────┐
        │ Authorized Target    │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Target Fingerprinting│
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Endpoint Discovery   │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Endpoint Ranking      │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Controlled Testing   │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Monitor Response     │
        │ Latency / Errors     │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Intelligent Budget   │
        │ Adjustment           │
        └──────────────────────┘
```

---

## 📈 What You Can Measure

IntelligentDDoS can help security teams investigate:

* Application response degradation
* Latency increases
* HTTP 5xx behavior
* HTTP 429 behavior
* Connection failures
* Timeout behavior
* Endpoint sensitivity to load
* WAF/CDN response behavior
* HTTP/1.1 vs HTTP/2 resilience
* Recovery behavior after testing

---

## 🛡️ Security Testing Use Cases

Potential authorized uses include:

### Web Application Resilience

Determine how an application behaves when exposed to controlled increases in HTTP traffic.

### WAF Testing

Evaluate whether an organization's defensive controls detect and respond to unusual traffic patterns.

### Rate-Limit Testing

Determine whether application and infrastructure rate limits behave as expected.

### Infrastructure Capacity Testing

Study latency, errors, and connection behavior during controlled stress tests.

### Incident Response Exercises

Generate controlled traffic conditions for blue-team detection and response exercises.

---

## ⚠️ Limitations

IntelligentDDoS is **not** a replacement for:

* Professional DDoS testing services
* Large-scale distributed infrastructure
* Dedicated load-testing platforms
* Production capacity planning
* WAF configuration reviews
* Network-level DDoS mitigation systems

The tool operates from the environment where it is executed and therefore does not reproduce every characteristic of a real distributed attack.

---

## 📜 Responsible Use

Only run IntelligentDDoS against:

* Systems you own
* Dedicated security-testing infrastructure
* Lab environments
* Staging environments
* Systems where you have explicit written authorization

Do not use it to disrupt:

* Public websites
* Third-party infrastructure
* Cloud services you do not control
* Networks belonging to other organizations
* Services without explicit authorization

The operator is responsible for ensuring that every test is authorized and conducted within an agreed scope.

---

## 🤝 Contributing

Contributions are welcome.

Potential areas for improvement include:

* Additional monitoring metrics
* Better reporting
* Improved endpoint discovery
* Additional HTTP testing capabilities
* Dashboard improvements
* Test-result export
* Integration with security monitoring platforms
* Additional safety controls

When contributing, preserve the project's authorization and safety mechanisms.

---

## 📄 License

Add the license appropriate for your project here.

For example:

```text
MIT License
```

Do not claim a license unless the repository actually contains that license.

---

## ⚠️ Disclaimer

**IntelligentDDoS is provided for authorized security testing, research, and resilience assessment.**

The developer does not authorize or encourage attacks against systems without permission.

You are responsible for complying with all applicable laws, contracts, testing agreements, and organizational policies.

---

## ⭐ Project

**IntelligentDDoS**

> Intelligent traffic simulation and controlled DDoS resilience testing for authorized security assessments.

## Usage

python3 intelligent_ddos.py doctor

# Launch the dashboard at http://127.0.0.1:8080
python3 intelligent_ddos.py ui

# Run a controlled test
python3 intelligent_ddos.py cli --target https://staging.yourserver --duration 120
