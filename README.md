
# Building a SOC + Honeynet in Azure (Live Traffic)
![image](https://github.com/user-attachments/assets/141e43b4-a458-4e86-a9d3-db31dbc6a5b7)

## Introduction

In this project, I set up a mini honeynet in Azure, where I collect logs from multiple resources into a Log Analytics Workspace. These logs are then processed by Microsoft Sentinel to generate attack maps, trigger alerts, and create incidents. I first measured security metrics in an insecure environment for 24 hours, applied security controls, then measured again for another 24 hours. The metrics tracked include:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![image]![before-security-controls](https://github.com/user-attachments/assets/66b147a4-6483-4a6b-8def-f4ede33bc43d)



## Architecture After Hardening / Security Controls
![image]![after_controls](https://github.com/user-attachments/assets/fa08bc93-a28c-4f7a-a364-c4868f0eab2a)



The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel


## Attack Maps Before Hardening / Security Controls
<img width="735" alt="Capture1" src="https://github.com/user-attachments/assets/a96e2851-8dd4-4826-a3c3-6eb081e63da1">
<br><br>
<img width="735" alt="Capture2" src="https://github.com/user-attachments/assets/6b1fa8bf-f773-4a06-8d75-8a71b421c5e0">
<br><br>
<img width="735" alt="Capture3" src="https://github.com/user-attachments/assets/51325333-e9cc-47d4-9270-7b820f541c06">
<br><br>
<img width="735" alt="Capture4" src="https://github.com/user-attachments/assets/93f0e175-6bbe-4b79-9be2-943958a42de2">
<br><br>

  
## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
<br>
| Start Time 12/9/24 2:37:30.727 AM
<br>
| Stop Time 12/10/24 2:37:30.727 AM

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 23771
| Syslog                   | 15782
| SecurityAlert            | 3
| SecurityIncident         | 183
| AzureNetworkAnalytics_CL | 2214

## Attack Maps After Hardening / Security Controls

<img width="231" alt="noresults" src="https://github.com/user-attachments/assets/2605f8c8-00a5-4880-b524-ca8725567793">
<br><br>

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
<br>
| Start Time 12/10/24 5:23:52.917 AM
<br>
| Stop Time 12/11/24 5:23:52.917 AM

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 655
| Syslog                   | 0
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0



## Summary

This project involved building a mini honeynet in Microsoft Azure, where logs were forwarded to a Log Analytics Workspace for analysis. Microsoft Sentinel was used to trigger alerts and generate incidents based on these logs. Metrics were collected in the insecure environment before and after applying security measures. The security events and incidents significantly decreased following the implementation of these controls, highlighting their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.


## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0<br>\| where TimeGenerated >= ago(24h)<br>\| count    |

