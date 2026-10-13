# Incident Response Investigation: DNS Data Exfiltration Hunt (Project)

## 📝 Overview
This repository contains an investigation report, log analysis artifacts, and automated parsing scripts from a simulated threat hunting engagement. Acting as an Incident Responder on Northwind Bank's security team, I identified a compromised workstation utilizing **DNS Tunneling (Exfiltration)** to smuggle stolen data past traditional firewall controls.

## 🎯 Investigation Objectives
1. **Baseline Network Noise:** Isolate standard resolver log data and identify deceptive telemetry decoys.
2. **Detect the Anomaly:** Unmask malicious machine beaconing through high-entropy subdomain analysis.
3. **Quantify the Breach:** Establish the precise timeline, compromised assets, and total data leakage.
4. **Reconstruct Content:** Extract, merge, and decode sequential Base32 chunks to recover the stolen secret.

---

## 🔍 Breach Metrics & Findings

| Metric | Details |
| :--- | :--- |
| **Compromised Asset** | Internal Client Host: `10.10.5.41` |
| **Command & Control (C2)** | `sync.cdn-telemetry.test` (Resolves to Attacker Range: `198.51.100.13`) |
| **Benign Traffic Decoy** | `cdn.telemetry-vendor.example` |
| **Exfiltration Volume** | Exactly **40 Bytes** (4 blocks × 10 bytes/block) |
| **Breach Window** | **2 minutes, 40 seconds** (Mar 14 08:56:21 to 08:59:01) |
| **Decoded Cleartext Payload** | `CYB101{dns_exfil_hidden_in_plain_sight!}` |

---
<img width="761" height="47" alt="Screenshot 2026-10-13 020136" src="https://github.com/user-attachments/assets/d0317819-9571-4cc0-a90a-49ea74d749b0" />

## 🛠️ Tactical Analysis & Validation

### 1. Isolating the Channel
While human-generated subdomains are legible (e.g., `://gstatic.com`), the malicious queries exhibited extreme **text entropy** and single-use labels. By piping the network logs through an inverted pattern match, I dropped the benign baseline noise to cleanly expose the beaconing host:

```bash
# Filter out baseline noise to isolate the attack traffic
grep -vE "duckduckgo\.com|telemetry-vendor" queries.log
```

### 2. Infrastructure Attribution (C2 Resolution)
To confirm where the stolen network traffic was routing, I utilized the `dig` utility targeting our local resolver to expose the underlying mapping of the parent domain. The query successfully unmasked the attacker's operational server IP address:

```bash
dig @localhost A sync.cdn-telemetry.test +short
```

<img width="727" height="42" alt="Screenshot 2026-10-13 012210" src="https://github.com/user-attachments/assets/46c09bae-49be-44b3-8294-2226323c61e8" />


### 3. Quantifying Total Data Volume
To determine the depth of the data breach, I audited the log file to identify the total volume of independent data packets delivered to the attacker's external server:

```bash
grep -c "sync.cdn-telemetry.test" /opt/dns-lab/logs/queries.log
```


<img width="1087" height="60" alt="Screenshot 2026-10-13 014705" src="https://github.com/user-attachments/assets/d09cf1f3-9adb-42f5-920b-eb55c5f413c7" />


*The count confirmed exactly 4 independent blocks of exfiltrated data. Since a 16-character Base32 chunk translates directly to 10 bytes of actual data, the entire data impact was scoped to exactly 40 bytes.*

### 4. Automated Decoding Pipeline
To prove the structural integrity of the breach data without manual transcription errors, I executed an automated Linux extraction pipeline to strip the parent domains, merge the sequential chunks, and decode the raw Base32 binary payload stream:

```bash
grep "sync.cdn-telemetry.test" /opt/dns-lab/logs/queries.log \
  | awk '{print \$6}' \
  | sed 's/\.sync\.cdn-telemetry\.test//' \
  | tr -d '\n' \
  | xargs -I {} echo {} \
  | base32 -d
```

<img width="1085" height="72" alt="Screenshot 2026-10-13 014848" src="https://github.com/user-attachments/assets/aa8eae6e-8b90-4814-a07e-fbde8901dc37" />


### 5. Technical Validation
Finally, the identified infrastructure was run through a validation check script to verify the target domain match against active network indicator lists:

```bash
check-c2 sync.cdn-telemetry.test
```

<img width="761" height="47" alt="Screenshot 2026-10-13 020136" src="https://github.com/user-attachments/assets/92873c97-4fb7-4865-8629-8433aac4db09" />


---

## 🛡️ Strategic Remediation & Engineering Controls

### The Architectural Problem
The client computer trusted its local resolver implicitly. Because firewalls must keep outbound **Port 53 (UDP/TCP)** unblocked to preserve basic internet connectivity, standard security rules fail to catch this attack. 

### Recommended Defensive Engineering
1. **DNS Tunneling Detection via Entropy Monitoring:** Implement SIEM/EDR detection alerts targeting any host generating a high frequency of completely unique, single-use, unpronounceable subdomain queries to an unrated or recently registered parent root domain.
2. **Response Policy Zones (RPZ):** Transform the internal resolver into a DNS Firewall by deploying real-time reputation blocklists to sinkhole suspicious incoming connection requests immediately.
3. **DNS Inspection Policies:** Force deep packet inspection on network edge perimeters to look for unusually long byte structures within individual DNS query labels.

