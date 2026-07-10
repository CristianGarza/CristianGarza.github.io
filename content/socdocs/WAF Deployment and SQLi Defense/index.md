---
title: "WAF Deployment and SQLi Defense"
summary: "Exploited a SQL injection auth bypass against OWASP Juice Shop, then deployed an Azure Application Gateway WAF to block the same attack and confirmed logging capture in KQL"
platform: Microsoft Azure · Application Gateway WAF v2
tags: [WAF, SQL Injection, Application Security, Azure, KQL]
placeholder: false
date: 2026-07-09
---

# Web Application Firewall Deployment & SQL Injection Defense
### Extending the Security Operations Lab into Application-Layer (Layer 7) Security

**Project Report — Part Three**
Platform: Microsoft Azure | Tooling: Azure Container Instances, Azure Application Gateway (WAF v2), OWASP Juice Shop, Log Analytics, KQL
*Builds on: Part One (Sentinel SIEM Deployment) and Part Two (MISP Threat Intelligence Integration)*

---

## Executive Summary

This report documents the third phase of a self-directed cloud security lab series, shifting focus from network- and endpoint-layer monitoring (Parts One and Two) to **application-layer (OSI Layer 7) security**. The objective was to deploy a deliberately vulnerable web application, attack it with a real exploitation technique, observe the attack succeed against an unprotected target, then place a **Web Application Firewall (WAF)** in front of the application and confirm the same attack is blocked — with the attempt fully logged for later analysis.

The vulnerable target was **OWASP Juice Shop**, an intentionally insecure web application maintained by OWASP for security training, deployed as a Docker container via **Azure Container Instances (ACI)**. A classic **SQL injection authentication bypass** (`' or 1=1--`) was used against the Juice Shop login form and succeeded without protection. An **Azure Application Gateway** configured with the **WAF v2** tier and a Web Application Firewall policy (using OWASP Core Rule Set–based managed rules) was then deployed in front of the container, acting as a reverse proxy and inspecting all inbound traffic. The same SQL injection payload was retried and correctly blocked with an HTTP 403 Forbidden response.

A key operational finding from this exercise was that the WAF policy defaults to **Detection mode** rather than **Prevention mode** — meaning it logs and flags malicious traffic without actually blocking it unless explicitly switched over. This distinction was called out as a real-world, business-impacting misconfiguration risk, not just a lab technicality. Finally, diagnostic logging was enabled on the Application Gateway, streaming all WAF logs into the same Log Analytics workspace used in Parts One and Two, where KQL queries were used to confirm the SQL injection attempt was captured and searchable.

## Project Objectives

- Deploy an intentionally vulnerable web application (OWASP Juice Shop) in Azure using a containerized approach.
- Demonstrate a real SQL injection authentication-bypass exploit against the unprotected application.
- Deploy an Azure Application Gateway with Web Application Firewall (WAF v2) capability in front of the vulnerable app.
- Confirm the WAF successfully blocks the same SQL injection attempt once properly configured.
- Identify and correct the WAF's default "Detection mode" behavior, switching it to actively preventive "Prevention mode."
- Enable diagnostic logging from the Application Gateway/WAF into Log Analytics and confirm the attack is visible and queryable via KQL.
- Understand WAFs in the broader context of OWASP Top 10 web application risks and real-world SOC/security engineering roles.

## Lab Environment & Architecture

This phase introduces application-layer infrastructure alongside the existing Azure environment from Parts One and Two.

| Component | Details |
|---|---|
| **Vulnerable Application** | OWASP Juice Shop — an intentionally vulnerable web app used for security training |
| **Application Hosting** | Azure Container Instances (ACI), pulling the Juice Shop image from Docker Hub ("Other registry" source) |
| **Container Registry Note** | Docker Hub used directly rather than Azure Container Registry, for simplicity; ACR was flagged as worth exploring separately |
| **Container Networking** | Public IP assigned to the container; application port switched from the image default (80) to port 3000 |
| **Resource Group** | Dedicated resource group created for this project (Juice Shop) |
| **Virtual Network** | New VNet created specifically to host the Application Gateway, with a /24 subnet (sized down from the default, since 65,000+ addresses were unnecessary) |
| **Perimeter Defense** | Azure Application Gateway, deployed with the **WAF v2** tier (not the container-oriented Application Gateway option) |
| **WAF Policy** | New WAF policy created and associated with the gateway; managed rule set covers OWASP Top 10 classes of attack (SQL injection, cross-site scripting, etc.) |
| **Gateway Frontend** | New public IP address assigned to the Application Gateway itself |
| **Gateway Backend Pool** | Configured to point at the Juice Shop container's public IP |
| **Routing** | Custom routing rule + listener (port 80 on the frontend) mapped to backend settings targeting port 3000 (the container's actual listening port) |
| **Logging** | Application Gateway diagnostic settings configured to send all logs to the existing Log Analytics workspace |
| **Query Language** | KQL, used to search WAF logs for SQL injection attempt records |

## Build Walkthrough

### 1. Deploying the Vulnerable Application (OWASP Juice Shop)

The vulnerable target application was deployed using **Azure Container Instances**, chosen for how quickly it allows spinning up a single containerized app without managing full orchestration infrastructure.

- A dedicated resource group ("juice shop" — Azure Container Instance names must be lowercase) was created to contain this project's resources, separate from the Parts One/Two resource groups.
- Under image source, **"Other registry"** was selected to pull directly from Docker Hub rather than first mirroring the image into Azure Container Registry. This was a deliberate simplicity trade-off; ACR was noted as a reasonable follow-up exploration given the cloud-security focus of this series.
- The full image path was specified (defaulting to the `latest` tag, since no specific version was pinned), with the image type set to **Public**.

**Docker Hub rate limiting:** Anonymous, unauthenticated image pulls from Docker Hub have been rate-limited since June 10, 2024. This surfaced during deployment as pull failures. Two workarounds were identified:
- Switching the Azure deployment region (since rate limiting appears to be applied per-IP-range, and different Microsoft regions may be less contended), or
- Creating a free Docker Hub account and configuring an **authenticated** image pull (registry login server `index.docker.io`, OS type left as Linux) instead of an anonymous one.

- Under networking, the container's port was changed from the image's default of **80** to **3000** — the actual port the Juice Shop application listens on internally.

Once deployed, the container's assigned public IP (on port 3000) was used to reach the running application directly in a browser, confirming Juice Shop was live and accessible.

### 2. Demonstrating the Vulnerability: SQL Injection Authentication Bypass

With Juice Shop confirmed reachable and unprotected, a classic SQL injection payload was used against the login form's **email/username field**:

```sql
' or 1=1--
```

With any arbitrary value entered in the password field, this payload was sufficient to bypass authentication entirely and log in successfully — a textbook demonstration of what happens when user input is concatenated directly into a SQL query without sanitization or parameterization. This step intentionally established a "before" baseline: the attack succeeds completely against the undefended application.

### 3. Building the Network Foundation for the WAF

Before the Application Gateway itself could be deployed, a dedicated **virtual network** was created:

- Placed in the same ("juice shop") resource group.
- Subnet sized to a **/24** CIDR block rather than a larger default range, since the lab does not require tens of thousands of addressable hosts.

### 4. Deploying the Application Gateway (WAF v2)

The Application Gateway was created carefully selecting the correct resource type — Azure separately lists an Application Gateway option associated with **container-based** workloads (Kubernetes-oriented), which is *not* what this build uses, despite the naming similarity.

- **Tier:** WAF v2 was selected, unlocking full Web Application Firewall functionality (over the standard, non-WAF Application Gateway tiers).
- **WAF Policy:** A new WAF policy was created and attached to the gateway. Optional **bot protection** was noted as available but not enabled for this build; policy defaults were otherwise accepted.
- Azure's own description of the WAF policy explicitly calls out protection against **SQL injection, cross-site scripting, and other OWASP Top 10 threats** — directly matching this lab's threat model.
- **Virtual network:** the gateway was attached to the VNet created in the previous step.
- **Frontend:** a new **public IP address** was created for the Application Gateway itself — this becomes the single public entry point users and the WAF share.
- **Backend pool:** configured with the Juice Shop container's public IP address as its only backend target.
- **Routing configuration:**
  - A routing rule and an associated **listener** were created, with the listener bound to **port 80** on the frontend.
  - **Backend settings** were configured to forward traffic to the backend pool on **port 3000** — matching the port the Juice Shop container was reconfigured to earlier. This is the critical mapping that makes the reverse-proxy behavior work: end users hit the gateway on port 80, and the gateway internally forwards to the container on port 3000.
- Deployment of the Application Gateway took roughly 15 minutes to complete.

### 5. Validating the WAF Is in the Traffic Path

Once deployed, browsing to the **Application Gateway's** public IP (not the container's IP) on the default port successfully loaded the Juice Shop application — confirming the gateway was correctly acting as a reverse proxy, transparently routing frontend traffic to the backend container on its non-standard port.

### 6. First (Failed) Attempt to Block the Attack — Detection Mode

The same SQL injection payload (`' or 1=1--`) was retried against the login form, this time through the WAF-fronted URL. **The injection still succeeded.**

Investigation revealed the root cause: newly created WAF policies in Azure default to **Detection mode**, not **Prevention mode**. In Detection mode, the WAF inspects and logs traffic matching its rule set but takes no blocking action — malicious requests are allowed straight through to the backend application.

This was highlighted as a realistic and consequential misconfiguration, not merely a lab quirk: security tooling left in a "monitor only" state provides the appearance of protection without the substance of it, and this exact category of mistake has contributed to real-world ransomware and breach incidents in production environments.

### 7. Correcting the Misconfiguration — Prevention Mode

The fix was straightforward once identified:

- Navigated to the Application Gateway's associated **WAF policy**.
- Used the **"Switch to prevention mode"** control at the top of the policy blade.

### 8. Confirming the Block

After switching to Prevention mode, the analyst logged out of the Juice Shop session and re-attempted the identical SQL injection login (`' or 1=1--`). This time, the request was met with an **HTTP 403 Forbidden** response, returned by the Application Gateway itself — confirming the WAF was now actively intercepting and blocking the malicious request before it ever reached the vulnerable backend application.

### 9. Enabling Diagnostic Logging

To ensure blocked (and attempted) attacks are actually visible to a SOC analyst rather than silently handled at the network edge, diagnostic logging was configured on the Application Gateway:

- Under **Monitoring → Diagnostic settings**, a new diagnostic setting was created.
- **All log categories** were selected for collection.
- Destination was set to **Send to Log Analytics workspace**, targeting the same default workspace created earlier in the overall project (shared with the Sentinel/MISP work from Parts One and Two).
- The diagnostic setting was named for clarity (e.g. "WAF logs").

### 10. Querying WAF Logs with KQL

With logging active, the **Logs** blade of the Log Analytics workspace was used to run KQL queries against the newly flowing Application Gateway/WAF log data, successfully locating the logged SQL injection attempt — confirming the full loop: **attack attempted → blocked by WAF → logged → discoverable via KQL for SOC review.**

## Key Findings & Observations

- Docker Hub's anonymous pull rate limiting (in effect since June 2024) can silently break "quickstart" container deployments that pull public images without authentication; switching regions or authenticating the pull are both valid workarounds.
- Azure lists a container-oriented "Application Gateway for Containers" option alongside the standard Application Gateway — the naming overlap is a genuine trap for anyone following along without care; the WAF-capable, non-Kubernetes option is the one needed for this style of deployment.
- **New WAF policies default to Detection mode, not Prevention mode.** This is arguably the single most important operational finding in this project: a WAF that is deployed but left in its default state provides logging/visibility only, not actual protection, and this exact gap has led to real production security incidents.
- A Web Application Firewall operating correctly is not a replacement for input sanitization at the application layer — it is a compensating control. The underlying Juice Shop application remains vulnerable to SQL injection; the WAF simply prevents that specific malicious pattern from reaching it.
- Centralizing Application Gateway/WAF diagnostic logs into the same Log Analytics workspace used for Sentinel (Parts One/Two) means application-layer attack telemetry can eventually be correlated alongside network- and endpoint-layer telemetry in a single SIEM view, rather than living in a separate silo.
- Even after WAF protection is confirmed working, the backend container in this build still retains its own public IP address directly — meaning it remains independently reachable and scannable by bots/scrapers unless separately locked down (see Limitations below).

## Limitations & Next Steps

This build intentionally stops at "WAF blocks a known attack and logs it" as a clear, demonstrable milestone. Several concrete extensions were identified:

- **Remove the backend's direct public exposure:** redeploy the Juice Shop container inside a private virtual network (no public IP on the container itself), so the Application Gateway becomes the *only* path to the application — closing the current gap where the container can still be discovered and reached directly, bypassing the WAF entirely.
- **WAF bypass testing:** actively attempt to bypass the WAF's managed rules using Juice Shop's other known vulnerabilities, to build a realistic understanding of WAF limitations and evasion techniques rather than assuming the WAF is infallible once enabled.
- **Expand rule coverage / tuning:** evaluate and tune the managed rule set (and consider enabling bot protection) against Juice Shop's broader vulnerability set (XSS, broken access control, etc.), not solely SQL injection.
- **Container registry migration:** move the Juice Shop image from Docker Hub into Azure Container Registry, both to avoid Docker Hub rate limiting long-term and to gain hands-on experience with ACR as an Azure-native service.
- **Alerting, not just logging:** build a Sentinel analytics rule against the ingested WAF logs so a blocked (or, more urgently, an allowed) SQL injection attempt generates an actual incident, rather than requiring an analyst to manually query the logs.
- **Correlate across the full lab:** cross-reference source IPs seen attacking the WAF/Juice Shop layer against the MISP-sourced threat intelligence indicators from Part Two, extending the "check IP against known-bad list" pattern established there into the application-security layer.

## Skills Demonstrated

- Deploying containerized applications on Azure using Azure Container Instances, including custom port configuration.
- Practical understanding of Docker Hub authentication and rate-limit workarounds.
- Hands-on demonstration of a SQL injection authentication-bypass exploit (OWASP Top 10 category).
- Designing and deploying Azure networking building blocks (VNet, subnetting) to support a security appliance.
- Deploying and configuring an Azure Application Gateway with WAF v2, including frontend/backend pool and routing-rule configuration.
- Web Application Firewall policy configuration and the operational distinction between Detection and Prevention modes.
- Diagnostic logging configuration, routing Application Gateway/WAF telemetry into a centralized Log Analytics workspace.
- KQL log analysis applied to application-layer (Layer 7) security telemetry.
- Applied understanding of the OWASP Top 10 and how WAFs serve as a compensating control at the application layer, in the broader context of enterprise security tooling and SOC/security engineering roles.

---
