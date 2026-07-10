---
title: "TI Integration with MISP"
summary: "Stood up an open-source MISP threat intel platform and built a Python/Azure Functions pipeline to push IOCs into Sentinel, enabling custom detections against malicious-confidence indicators"
platform: Microsoft Azure · MISP · Docker
tags: [Threat Intelligence, MISP, Azure Functions, Python, Sentinel]
placeholder: false
date: 2026-07-09
---

# Threat Intelligence Integration with MISP
### Extending the Security Operations Monitoring Lab with an Open-Source Threat Intelligence Platform

**Project Report — Part Two**
Platform: Microsoft Azure, Ubuntu (Linux), Docker | Tooling: Microsoft Sentinel, MISP, Azure Functions, Python
*Builds on: Part One — Cloud SIEM Deployment with Microsoft Sentinel*

---

## Executive Summary

This report documents the second phase of a self-directed Security Operations Center (SOC) lab project: integrating an independent, open-source threat intelligence platform into the Microsoft Sentinel environment built in Part One. Rather than relying solely on Microsoft's built-in threat intelligence, this phase stood up **MISP (Malware Information Sharing Platform)** — an open-source threat intelligence platform — on a dedicated Linux virtual machine, populated it with publicly available threat feeds, and built a custom pipeline to push MISP's indicators of compromise (IOCs) into Microsoft Sentinel on a recurring schedule.

The pipeline consisted of a Dockerized MISP instance running on an Ubuntu VM, a set of default open threat feeds enabled and synced within MISP, an Azure AD (Entra ID) App Registration used to authenticate against the Sentinel workspace, and an Azure Function App running a Python script that periodically pulls indicators from MISP via its REST API and uploads them to Sentinel via the Microsoft Upload Indicators API. Once connected, Sentinel began ingesting hundreds of thousands of threat indicators — IP addresses, confidence scores, and associated metadata — that can be referenced directly in KQL queries and used to build custom detections, such as flagging Honeypot RDP connections that originate from IP addresses with a 100% malicious-confidence score in MISP.

This phase deliberately avoided Microsoft's prepackaged threat intelligence connector and instead built an independent, source-controlled indicator pipeline — a more realistic reflection of how a SOC might integrate third-party or community threat intelligence in the real world.

## Project Objectives

- Deploy an independent, open-source threat intelligence platform (MISP) rather than relying solely on Microsoft's built-in threat intelligence.
- Ingest and enable free, publicly available threat intelligence feeds within MISP.
- Establish secure, authenticated connectivity between MISP and Microsoft Sentinel using Azure AD App Registration.
- Build and deploy a custom Python-based Azure Function to automate indicator delivery from MISP to Sentinel on a recurring schedule.
- Validate that threat indicators (IPs, confidence scores, tags) successfully land in Sentinel and can be queried and used in custom detection logic.
- Demonstrate how ingested threat intelligence can be correlated against existing telemetry (e.g. the Part One RDP Honeypot) to identify high-confidence malicious activity.

## Lab Environment & Architecture

This phase adds a second virtual machine and several supporting Azure resources to the environment established in Part One.

| Component | Details |
|---|---|
| **Threat Intel Platform** | MISP (Malware Information Sharing Platform), open-source, self-hosted |
| **Hosting VM** | New Ubuntu Linux virtual machine, deployed via Azure VM creation |
| **Containerization** | Docker Engine + Docker Compose, installed on the Ubuntu VM |
| **MISP Deployment Method** | Official MISP Docker image, cloned from GitHub and run via `docker compose` |
| **Exposed Ports** | 443 (HTTPS, for MISP web UI) opened via NSG inbound rule; SSH already open for management |
| **Threat Feeds** | MISP's default set of free, public feeds, imported via JSON and enabled/synced |
| **Identity for Integration** | Azure AD (Entra ID) App Registration, granted the **Microsoft Sentinel Contributor** role on the Log Analytics workspace |
| **Secrets Management** | Client secret (App Registration) and MISP API authentication key, stored as Function App environment variables (in place of Azure Key Vault, which did not work reliably with the reference script) |
| **Automation Compute** | Azure Function App (Python 3.11, App Service plan — Consumption plan lacked sufficient resources) |
| **Integration Script** | Community-maintained "MISP to Sentinel" Python function, deployed via VS Code's Azure Functions extension |
| **Ingestion API** | Microsoft **Upload Indicators API** (the alternative Graph API path is deprecated) |
| **Data Connector (Sentinel side)** | MISP data connector, installed from the Sentinel Content Hub |
| **Schedule** | Timer-triggered function, Cron expression for every 2 hours; function timeout set according to hosting plan (10 min–24 hr) |

## Build Walkthrough

### 1. Provisioning the MISP Virtual Machine

A second Azure virtual machine was created specifically to host MISP, kept separate from the Windows Honeypot VM built in Part One.

- **OS:** Ubuntu Linux (chosen deliberately to get hands-on Linux experience, since the Part One lab used only Windows and Mac endpoints).
- **Region:** kept consistent with other lab resources to avoid latency, and to avoid regions with limited availability.
- **Sizing:** default VM size was used; note that this VM carries a meaningfully higher running cost (~$70/month, ~10 cents/hour) than the Part One VM, reflecting the larger resource footprint of running MISP + Docker.
- **Access:** connected to via SSH using Azure's built-in browser SSH client, rather than RDP.

### 2. Installing Docker on the Ubuntu VM

Docker was installed following Docker's official Linux installation instructions:

- Added Docker's official APT repository.
- Installed the Docker Engine and Docker Compose plugin.

One practical issue encountered: pasting Docker's full multi-line install script as a single block caused package-resolution errors (Docker Compose plugin not found). Running the commands in smaller sections resolved this — a useful troubleshooting note for anyone repeating this build.

- Installation was verified by running the standard `hello-world` test container, confirming the Docker Engine was functioning correctly.

### 3. Deploying MISP via Docker

MISP provides an official, prepackaged Docker image and Compose configuration on GitHub.

- The MISP Docker repository was cloned directly onto the Ubuntu VM via `git clone`.
- `template.env` was copied to `.env` (`cp template.env .env`), then edited with `nano` to set the `BASE_URL` value to the VM's public IP address.
- The stack was pulled and started:
  ```bash
  sudo docker compose pull
  sudo docker compose up
  ```
- Once running, `sudo docker ps` confirmed the containers were live and listening on ports 80 and 443.

### 4. Network Configuration

By default, only SSH was open on the Ubuntu VM's Network Security Group. An additional inbound rule was added to allow **TCP port 443** from any source, enabling HTTPS access to the MISP web interface from the analyst's own machine or from the other Honeypot VM in the same tenant.

Navigating to `https://<VM public IP>` presented a browser security warning (expected, since no trusted TLS certificate was configured) — this was bypassed via the browser's "Advanced" / proceed option for lab purposes.

### 5. Initial MISP Configuration

- Logged in to the MISP web UI using the documented default credentials (`admin@admin.test` / `admin`).
- **Immediately changed the default admin password** via the account/profile settings — leaving default credentials on a public-facing instance is an obvious and unnecessary risk, even in a lab.

### 6. Enabling Threat Intelligence Feeds

MISP ships with a default set of free, publicly available threat feeds, distributed in JSON format.

- The feed list (JSON) was retrieved from MISP's documentation/GitHub and imported directly into MISP via **Sync Actions → Feeds → Import feeds from JSON**.
- Each of the (five) resulting feed pages was individually set to **Enabled**.
- Feeds were then fetched and cached, a process that runs in the background and can be monitored under **Administration → Jobs**, where sync jobs appear as queued, running, or completed.
- Once synced, the MISP homepage populated with live indicator data (e.g. malicious IP addresses tied to specific feed sources), confirming the feeds were active and current.

### 7. Registering an Azure AD App for Sentinel Access

To allow an external process to write indicators into the Sentinel workspace, an Azure AD (Entra ID) **App Registration** was created:

- Created under **App registrations → New registration**, with defaults left otherwise unchanged.
- Recorded the **Application (client) ID**, **Object ID**, and **Tenant ID** for later use.
- Under **Certificates & secrets**, a new **client secret** was generated — its *value* (not just its ID) was copied immediately, since it is only ever displayed once.
- The app was then granted the **Microsoft Sentinel Contributor** role directly on the Log Analytics workspace (via **Access control (IAM) → Add role assignment → Microsoft Sentinel Contributor → select the app as a member**), giving it permission to write data into that Sentinel instance.

### 8. Generating a MISP API Key

To allow the integration script to pull data out of MISP, a MISP **authentication (API) key** was generated under **Administration → List Auth Keys → Add authentication key**. As with the Azure client secret, the key's value is shown only once and was saved immediately. Key restrictions (allowed IPs, expiration) are available for additional hardening but were left permissive for this lab.

> **Note on secrets handling:** The reference instructions called for storing these secrets in an Azure Key Vault. In practice, the companion Python script did not correctly read values back out of Key Vault, and the Key Vault access-policy configuration added significant friction without a working payoff. As a pragmatic (though **not best-practice**) workaround for this lab, secrets were instead stored as Azure Function App **environment variables**. This is explicitly called out as a shortcut appropriate for a disposable lab environment — a production deployment should use Key Vault (or an equivalent managed secrets store) with correctly scoped access policies.

### 9. Building the Integration: Azure Function App

An Azure Function App was created to host the scheduled MISP-to-Sentinel integration script.

- **Hosting plan:** App Service plan (the Consumption plan did not provide sufficient resources to run the deployment successfully; Flex Consumption was noted as a viable alternative).
- **Runtime:** Python 3.11.
- **Region:** deliberately double-checked, since it defaulted to an unintended region (Canada) during creation.

### 10. Deploying the Python Function

- The community "MISP to Sentinel" repository was downloaded (as a ZIP) from GitHub and opened in Visual Studio Code.
- The VS Code Azure Functions/Resources extension was used to sign in to the same Azure tenant used throughout the lab.
- Two adjustments were made to the reference source before deployment, since the published instructions did not fully match the current code:
  - Corrected a variable name so it matched what the script expected (`misp_key` vs. a mismatched name).
  - Removed multi-tenant handling logic in the main `init.py` function, since this lab uses a single Azure tenant and the multi-tenant code path threw type errors (expecting an integer) when left in place.
- The function was deployed directly to the previously created Function App via VS Code's **"Deploy to Function App"** action.

### 11. Configuring Environment Variables

The deployed function reads its configuration from environment variables, matched by name to what `config.py` expects. The following were added under the Function App's **Configuration → Environment variables**:

| Variable | Value source |
|---|---|
| `tenant_id` | Tenant ID from the App Registration |
| `client_id` | Application (client) ID from the App Registration |
| `client_secret` | Client secret value generated earlier |
| `workspace_id` | Log Analytics workspace ID |
| `misp_key` | MISP API authentication key |
| `misp_url` | Public URL/IP of the MISP instance |
| `timer_trigger_schedule` | Cron expression controlling run frequency (set to every 2 hours) |
| `function_timeout` | Set according to hosting plan — 10 minutes (Consumption) up to 24 hours (Premium/Dedicated), based on expected indicator volume |

Exact variable naming was critical, since the script performs direct name-based lookups against these environment variables.

### 12. Installing the Sentinel-Side MISP Data Connector

In parallel with the Function App work, the **MISP** data connector was installed from the Sentinel **Content Hub**, mirroring the Content Hub workflow used for the Windows Security Events connector in Part One. Immediately after installation the connector showed as "Disconnected" — expected, since it has no active data source until the Function App begins pushing data to it.

### 13. Testing and Validation

Rather than waiting for the full 2-hour schedule to elapse to discover a configuration error, the function was tested directly:

- From the Function App's **Code + Test** blade, the function was manually run/tested, expecting an HTTP `202 Accepted` response.
- The **Invocations and more → Logs** view was used (in a separate tab) to watch execution in near real time.
- Console output confirmed the script was using the Microsoft Upload Indicators API (not the deprecated Graph API path) and that `tenant_id`, `client_id`, `workspace_id`, and `client_secret` were all successfully loaded from environment variables.
- Initial attempts failed at the build/deploy stage intermittently; redeploying from VS Code resolved this. This appears to be an occasional platform-level flakiness rather than a configuration error.
- Indicator ingestion into Sentinel was **not instantaneous** — actual data availability in Sentinel's Threat Intelligence table lagged by anywhere from tens of minutes to a few hours after a successful function run, which is an important expectation to set when validating this kind of pipeline.
- Once data arrived, the MISP data connector's status changed to **Connected**, with a recent "last log received" timestamp, and the Sentinel Threat Intelligence indicator table populated with real records — including source tags, associated network/destination IPs, and a confidence score field.

### 14. Querying and Using the Ingested Threat Intelligence

With indicators flowing, they became queryable and usable in detection logic:

- A simple KQL filter for `ConfidenceScore == 100` isolated the small subset of indicators MISP's feeds consider maximally confident as malicious, out of the hundreds of thousands ingested.
- This indicator set can be referenced inside a Sentinel Analytics Rule to **cross-reference live telemetry against threat intelligence** — for example, checking whether an IP address seen connecting to the Part One RDP Honeypot also appears in the high-confidence malicious-IP list pulled from MISP, enabling a custom, evidence-backed detection rather than a single-source alert.

## Key Findings & Observations

- Multi-line shell scripts copy-pasted as a single block into a fresh Ubuntu SSH session can silently fail mid-way (e.g. missing the Docker Compose plugin); pasting and executing in smaller sections was a reliable workaround.
- Following official third-party integration guides exactly does not guarantee success: both the Key Vault-based secrets flow and parts of the reference Python script needed to be adapted (variable naming, removal of unused multi-tenant logic) to work in this environment.
- Threat intelligence pipelines are not real-time: expect a meaningful delay — minutes to hours — between a successful ingestion run and data actually appearing and being queryable in Sentinel.
- The Azure Function **Consumption** hosting plan was insufficient for this workload; an App Service (or Flex Consumption) plan was required.
- Storing secrets as plain Function App environment variables is a functional shortcut for a disposable lab, but is explicitly **not** how production secrets should be handled — Azure Key Vault (correctly configured) remains the appropriate approach outside of a lab context.
- Building an independent threat intelligence source (MISP) rather than depending only on Microsoft's built-in feed diversifies detection coverage and better reflects how real SOC teams often blend vendor and community/open-source intelligence.
- MISP's confidence score field is a practical, low-effort way to triage an otherwise very large indicator set down to a small number of high-value, high-confidence entries suitable for active alerting.

## Limitations & Next Steps

- **Secrets management:** migrate credentials (client secret, MISP API key) from Function App environment variables into Azure Key Vault with correctly scoped access policies, resolving the integration issues encountered during this build.
- **TLS/certificate hardening:** the MISP instance is currently served without a trusted TLS certificate; adding one (e.g. via Let's Encrypt) would remove the browser security warning and better reflect a production-appropriate deployment.
- **Automated correlation rules:** build out dedicated Sentinel Analytics Rules that actively join Honeypot/security event telemetry against the MISP-sourced Threat Intelligence table (e.g. alert when a Honeypot connection's source IP matches a 100%-confidence MISP indicator), rather than only querying the TI table manually.
- **Feed curation:** evaluate and prune MISP's default feed list over time — not every free feed will be equally relevant or high-quality for this lab's threat model.
- **Cost management:** the MISP VM and always-on Function App carry ongoing cost; both should be deallocated/deleted when not actively in use to preserve trial credit.
- **Multi-source enrichment:** consider also enabling Microsoft's own built-in threat intelligence alongside MISP for comparison, rather than treating the two as mutually exclusive.

## Skills Demonstrated

- Linux system administration fundamentals (Ubuntu, SSH, package management, file editing with `nano`).
- Docker and Docker Compose: installing Docker Engine, deploying a multi-container application from an official image.
- Deploying and hardening a self-hosted, open-source threat intelligence platform (MISP), including changing default credentials.
- Azure networking: NSG inbound rule configuration for a Linux-hosted web service.
- Azure Active Directory (Entra ID) App Registration and role-based access control (RBAC), including scoped role assignment (Sentinel Contributor).
- Secrets and API key generation and management (Azure client secrets, MISP authentication keys).
- Serverless automation: building, configuring, and deploying a Python-based Azure Function App, including environment variable configuration and Cron-based scheduling.
- Practical debugging of a third-party integration: identifying and correcting mismatches between published documentation and actual source code behavior.
- Threat intelligence fundamentals: understanding IOC feeds, confidence scoring, and how ingested threat intelligence supports custom detection engineering.
- End-to-end validation of an asynchronous data pipeline (MISP → Azure Function → Sentinel) using function invocation logs and connector status.

---
