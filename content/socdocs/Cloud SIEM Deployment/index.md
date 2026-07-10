---
title: "Cloud SIEM Deployment"
summary: "Deployed Microsoft Sentinel over an internet-exposed VM, streamed Windows Security Events via AMA, and wrote a Scheduled Analytics Rule that turns successful RDP sign-ins into incidents"
platform: Microsoft Azure · Microsoft Sentinel
tags: [SIEM, KQL, Detection Engineering, Azure Monitor, Log Analytics]
placeholder: false
date: 2026-07-08
---

# Cloud SIEM Deployment
### Building a Security Operations Monitoring Lab with Microsoft Sentinel

**Project Report**
Platform: Microsoft Azure | Tooling: Microsoft Sentinel, Log Analytics, KQL

---

## Executive Summary

This report documents the design, deployment, and validation of a cloud-based Security Information and Event Management (SIEM) monitoring lab built on Microsoft Azure using Microsoft Sentinel. The objective of the project was to gain hands-on, end-to-end experience with the core workflow of a modern Security Operations Center (SOC): provisioning monitored infrastructure, centralizing log collection, and building detection logic that turns raw telemetry into actionable security incidents.

The lab consisted of a single internet-facing Windows virtual machine intentionally configured to accept inbound Remote Desktop Protocol (RDP) connections on port 3389 from any source. This VM's Windows Security Event logs were streamed into a Log Analytics workspace via the Azure Monitor Agent (AMA), ingested into Microsoft Sentinel, and queried using Kusto Query Language (KQL). A custom Scheduled Analytics Rule was then built to detect successful, non-system RDP sign-ins — a strong indicator of either legitimate access or a successful brute-force compromise — and to automatically generate a Sentinel incident when that condition was met.

The rule was validated in a live environment: after the detection logic went active, the engineer signed in to the exposed VM via RDP, and within the configured polling window Sentinel correctly generated a corresponding security incident, confirming the full detection pipeline from raw event to actionable alert.

## Project Objectives

- Provision and configure cloud infrastructure (VM, network, Log Analytics workspace) to support centralized security monitoring.
- Deploy Microsoft Sentinel as a cloud-native SIEM and connect it to a live data source.
- Configure a data connector and data collection rule to stream Windows Security Events into Sentinel.
- Use KQL to query and filter raw security event logs, distinguishing meaningful signal (interactive user logons) from noise (system account activity).
- Author a custom Scheduled Analytics Rule that automatically detects successful RDP sign-ins and raises a Sentinel incident.
- Validate the complete detection pipeline against a real, self-generated login event.

## Lab Environment & Architecture

All resources were deployed under a single Azure resource group to keep the lab self-contained and easy to tear down. The core components and their roles are summarized below.

| Component | Details |
|---|---|
| **Cloud Platform** | Microsoft Azure (Pay-As-You-Go / free-trial credit) |
| **Resource Group** | Single resource group containing all lab assets |
| **Monitored Endpoint** | Windows virtual machine, deployed with a public IP address |
| **Exposure / Attack Surface** | Inbound Network Security Group (NSG) rule allowing RDP (TCP 3389) from any source |
| **Log Aggregation** | Azure Log Analytics workspace |
| **SIEM Platform** | Microsoft Sentinel, connected to the Log Analytics workspace |
| **Data Connector** | "Windows Security Events via AMA" (Azure Monitor Agent), installed from the Sentinel Content Hub |
| **Ingestion Mechanism** | Data Collection Rule (DCR) targeting the VM, configured to collect all Windows Security Events |
| **Query Language** | Kusto Query Language (KQL), used interactively in Sentinel Logs |
| **Detection Logic** | Custom Scheduled Analytics Rule: "Successful Local Sign Ins" |
| **Response Mechanism (this phase)** | Automatic Sentinel incident creation on rule trigger; no SOAR automation configured in Part One |

## Build Walkthrough

### 1. Virtual Machine Provisioning

A new resource group was created to logically contain every asset used in the lab. Within it, a Windows virtual machine was deployed using Azure's "preset configuration" quick-create path, which pre-populates sensible defaults for size, disk, and image.

- **Image:** Windows Pro (Windows 11), sized for general-purpose testing rather than production workloads.
- **Administrator credentials:** a simple, deliberately guessable username/password pair — intentional, since the objective is to attract or simulate authentication activity against the box rather than harden it.
- **Networking:** default virtual network and auto-generated public IP address, with an inbound NSG rule allowing RDP (port 3389) from any source (0.0.0.0/0).
- **Disks, monitoring, and management settings** were left at their defaults, since this VM's only purpose is to generate authentication telemetry, not to host a workload.

This configuration is a deliberate departure from security best practice — a production system would never expose RDP directly to the internet. Here, that exposure is the point: it guarantees a steady, realistic stream of authentication events (failed and successful) for the SIEM to observe and act on.

### 2. Log Analytics Workspace

A Log Analytics workspace was created in the same Azure region as the virtual machine and placed in the same resource group. Keeping resources co-located in one region avoids unnecessary cross-region data transfer latency and simplifies lifecycle management (the whole lab can be deleted by deleting the resource group).

The Log Analytics workspace is the storage and query engine underneath Sentinel — Sentinel itself does not store data independently, it is deployed "on top of" a workspace.

### 3. Microsoft Sentinel Deployment

Microsoft Sentinel was enabled directly against the newly created Log Analytics workspace. Once active, the Sentinel Overview page confirmed the expected starting state: zero incidents, zero automation rules, and zero connected data sources — since no data connector had been configured yet.

### 4. Data Connector & Data Collection Rule

With the VM and Sentinel both live, the next step was to get the VM's event logs flowing into Sentinel. This requires a data connector, installed from the Sentinel Content Hub.

- The "Windows Security Events" solution was installed from the Content Hub, which provisions the associated data connectors, analytics rule templates, and workbooks as a bundle.
- Of the two available ingestion connectors — the legacy Log Analytics agent and the modern Azure Monitor Agent (AMA) — the AMA-based connector ("Windows Security Events via AMA") was selected, since Microsoft has deprecated the legacy agent path.
- A Data Collection Rule (DCR) named to reflect its purpose (Windows events → Sentinel) was created, targeting the lab VM specifically and configured to collect all Security Events rather than a filtered subset.

Before this step, the workspace's Agents page correctly showed zero connected Windows computers, confirming that although the VM was generating security events locally (as any Windows host does), none of that data had yet reached Sentinel. After the DCR was created and given time to take effect, Security Events began appearing in the workspace.

### 5. Querying Raw Telemetry with KQL

With data flowing, the Logs blade in Sentinel was used to run Kusto Query Language (KQL) queries directly against the `SecurityEvent` table. An initial exploratory query filtered for successful activity:

```kql
SecurityEvent
| where Activity contains "success"
```

This surfaced sign-in events, but nearly all of them belonged to built-in system accounts (e.g. `NT AUTHORITY\SYSTEM`) performing routine machine-level operations — not the kind of human-driven RDP logon a SOC analyst would care about. This is an important and realistic finding: raw security logs are dominated by noise, and meaningful detection requires actively filtering out expected system activity to isolate the signal (in this case, an actual interactive account successfully authenticating over RDP).

### 6. Custom Analytics Rule: "Successful Local Sign Ins"

A new Scheduled Analytics Rule was authored in Sentinel to operationalize this finding:

- **Name:** Successful Local Sign Ins
- **Severity:** Medium
- **MITRE ATT&CK tactic mapped:** Initial Access — appropriate, since a successful RDP logon on an internet-exposed host is a classic initial-access vector.
- **Rule logic:** query for successful sign-in activity, explicitly excluding system accounts, so the rule only fires on genuine interactive logons.
- **Schedule:** runs every 5 minutes, looking back over the last 5 minutes of data — a near real-time detection cadence.
- **Alert threshold:** trigger when the query returns more than 0 results, with all matching events grouped into a single alert per run.
- **Incident settings:** configured to automatically create a Sentinel incident from any alert this rule generates.

This rule illustrates the core SIEM value proposition in miniature: converting a mountain of routine log data into a small number of specific, actionable alerts that map to a recognized adversary technique.

### 7. Validation

To confirm the pipeline worked end-to-end rather than just "looking correct" in configuration, the rule was tested against a live event: the analyst signed in to the exposed VM over RDP using its public IP address. Within the rule's 5-minute polling window, Microsoft Sentinel correctly generated a new incident — "Successful Local Sign Ins" — visible on the Incidents page with a Medium severity, an associated alert, and the Initial Access tactic tagged.

This confirmed the full chain was functioning:

`Endpoint activity → Windows Security Event log → Azure Monitor Agent → Data Collection Rule → Log Analytics workspace → Sentinel Analytics Rule → Sentinel Incident`

## Key Findings & Observations

- Exposing RDP directly to the internet, even briefly, reliably generates authentication traffic — a useful property for lab telemetry generation, but a real-world reminder of why RDP should never be internet-facing in production without additional controls (VPN, Bastion, Just-In-Time access, MFA).
- Raw `SecurityEvent` data is dominated by system and machine account noise; a naive "successful sign-in" filter is not sufficient on its own — meaningful detections require actively excluding expected background activity.
- Microsoft is deprecating the legacy Log Analytics agent in favor of the Azure Monitor Agent (AMA); new builds should default to AMA-based connectors going forward.
- Sentinel's Content Hub bundles a data connector together with matching analytics rule templates and workbooks, which meaningfully speeds up onboarding a new log source compared to configuring each piece manually.
- A 5-minute scheduled query interval offers a reasonable balance between near real-time detection and query/compute cost for a lab-scale deployment.

## Limitations & Next Steps

This build represents the foundational data-collection-and-detection stage of a SOC workflow. Several extensions were identified as logical next phases:

- **Threat intelligence enrichment:** ingesting external indicator-of-compromise (IOC) feeds via API into Sentinel, rather than relying solely on built-in Microsoft threat intelligence.
- **SOAR automation:** attaching an automation rule / Logic App playbook to the analytics rule so that an incident triggers an automated response (e.g. notification, IP block, ticket creation) rather than requiring manual analyst triage.
- **Additional data sources:** onboarding a Linux VM and its corresponding data connector to broaden detection coverage beyond Windows.
- **Refined detection logic:** expanding beyond a single "successful sign-in" rule to cover brute-force detection (high-volume failed logons), geo-anomalous logons, and other MITRE ATT&CK-mapped techniques.
- **Hardening the lab after data collection:** since RDP exposure was intentional for telemetry generation, the port should be closed or replaced with Just-In-Time access once the exercise is complete.

## Skills Demonstrated

- Azure resource provisioning: resource groups, virtual machines, virtual networks, and Network Security Groups.
- Centralized log management using Azure Log Analytics workspaces.
- Deployment and configuration of Microsoft Sentinel as a cloud-native SIEM.
- Data connector and Data Collection Rule configuration for telemetry ingestion (Azure Monitor Agent).
- Kusto Query Language (KQL) for log analysis and signal-to-noise filtering.
- Detection engineering: authoring a Scheduled Analytics Rule mapped to a MITRE ATT&CK tactic (Initial Access).
- End-to-end validation of a security detection pipeline against live, self-generated activity.

---

*Report prepared as a portfolio summary of a self-directed Azure Sentinel SIEM lab project.*