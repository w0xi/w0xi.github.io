---
layout: post
title: "Chasing Certighost's Tail"
date: 2026-08-18
categories: [soc]
tags: [zeek, active-directory, adcs, certighost, cve-2026-54121, netlogon]
---

*SOC · Medium · SIEM · 7 questions*

SOC investigation lab built on CVE-2026-54121 (Certighost), a critical
Active Directory Certificate Services flaw patched in July 2026. The lab
follows the attack chain from a low-privilege domain user through machine
account creation, CA callback abuse, and Netlogon relay, reconstructed
from Zeek network sensor logs.

## At a glance

| | |
|---|---|
| Artifacts | `Zeek Logs and .pcap` |
| DC / CA | `172.16.14.10` |
| Attacker workstation | `172.16.14.50` |
| Launching account | `a.novak` (low-privilege, IT helpdesk) |
| Rogue machine account | `GHOSTJVSRGDNR$` |
| Questions | 7 |

## Background

CVE-2026-54121 was disclosed by Kudelski Security in May 2026 and patched
in July 2026. CVSS 8.8. It abuses the Active Directory Certificate Services
chase-fallback mechanism: when a certificate request embeds a custom `cdc`
attribute pointing to an attacker-controlled host, the CA performs a secondary
identity lookup against that host rather than a legitimate Domain Controller.
The attacker's rogue SMB and LDAP servers answer the CA's lookup with the
target DC's identity, causing the CA to issue a certificate belonging to the
Domain Controller. The attacker then uses that certificate for PKINIT
authentication as the DC.

Any authenticated low-privilege domain user can trigger this chain. No admin
rights, no elevated credentials, no user interaction required.

## Scenario

A security alert fired on your SOC platform at 23:29 UTC flagging unusual
outbound SMB activity from an internal server. You have been handed a set of
Zeek network sensor logs covering the 35-second window around the alert. Your
job is to triage the activity, reconstruct the attack chain, and articulate
the detection logic that should have caught this earlier.

The investigation interface is self-contained: open it in any browser, no setup required.

## Investigation interface

<a href="https://w0xi.github.io/certighost/sensors.html" target="_blank" rel="noopener noreferrer" style="display:inline-block;padding:10px 20px;background:#2d2d2d;color:#fff;text-decoration:none;border-radius:4px;font-family:monospace;">Open Investigation </a>

All seven Zeek log types are pre-loaded.

For packet-level analysis: [`certighost_final.pcap`](https://github.com/w0xi/w0xi.github.io/releases/download/v1.0/certighost_final.pcap) (optional, not required for any question)

## MITRE ATT&CK mapping

| Tactic | ID | Technique | Evidence observed |
|---|---|---|---|
| Persistence | [T1136.002](https://attack.mitre.org/techniques/T1136/002/) | Create Account: Domain Account | `GHOSTJVSRGDNR$` created by `a.novak` via SAMR; visible in `ntlm.log` with `success=T` |
| Credential Access | [T1649](https://attack.mitre.org/techniques/T1649/) | Steal or Forge Authentication Certificates | Certificate request embedding malicious `cdc` attribute; CA connects back to attacker host |
| Credential Access | [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Rogue SMB / LDAP servers intercept CA's identity-resolution callback; relay via Netlogon |
| Privilege Escalation | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Valid Accounts: Domain Accounts | `a.novak` (standard user) used to initiate the full chain; no admin rights required |
| Lateral Movement | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Use Alternate Authentication Material: Pass the Certificate | PKINIT with forged DC certificate enables authentication as the Domain Controller |

## Questions

1. Which domain user account initiated the attack chain, and did their authentication succeed?
2. What is the full name of the rogue machine account created by the attacker (including the `$` suffix)?
3. The most anomalous connection in `conn.log` reveals the vulnerability being exploited. Which host initiated it, to which destination IP and port, and why is this direction suspicious?
4. During the chase, the CA authenticated to the attacker's rogue SMB server. What account identity did it present, and what does this reveal about the attacker's goal?
5. `dce_rpc.log` records the full Netlogon relay sequence. List all four operations in the order they appear.
6. What is the NetBIOS computer name of the rogue SMB server the CA connected to?
7. Write a plain-language detection rule that would catch this attack at the network layer, based only on what you observe in `conn.log` and `ntlm.log`. Your rule must be specific enough not to fire on benign AD CS enrollment traffic.

## Walkthrough

### 1. Low-privilege entry point

The first entry in `ntlm.log` establishes the starting point: `a.novak`
authenticating to `172.16.14.10:445` with `success=T`. Standard domain user,
IT helpdesk, no elevated rights. This is the only credential needed to trigger
the full chain: the attack requires nothing more than a valid domain account.

A second `ntlm.log` entry immediately follows: `GHOSTJVSRGDNR$` also authenticating
to the DC with `success=T`. The attacker used `a.novak`'s credentials to create
a throwaway machine account within the default `ms-DS-MachineAccountQuota`
of 10 that every domain user has by default.

### 2. The certificate request and the chase

The attacker submits a certificate request to the CA (`172.16.14.10`) with a
crafted `cdc` attribute pointing to their rogue host at `172.16.14.50`. The CA,
following its normal identity-resolution procedure, connects back to that address
to verify the requestor's identity.

This is the chase and it is the single most important signal in the capture.

`conn.log` shows eight connections where **`172.16.14.10` (the DC/CA) is the
originator** and `172.16.14.50:445` (the attacker workstation) is the destination.
A Domain Controller initiating outbound SMB to a workstation is the inversion
of normal AD traffic flow. In a healthy domain, servers authenticate clients
not the other way around.

![](/screenshots/1siem.png)

### 3. Identity impersonation via Netlogon relay

When the CA connects to the rogue SMB server, it authenticates using its own
machine account identity. `ntlm.log` records this plainly: `DC01$` from
`CASCADELOGISTIC` domain authenticating to `GHOSTJVSRGDNR` the rogue server
name the attacker registered.

The attacker's rogue server then relays this authentication to the real DC via
Netlogon. `dce_rpc.log` records the full relay sequence for each attempt:

![](/screenshots/2siem.png)

That log goes further into 8 complete Netlogon sessions, each one a relay attempt using the GHOST
machine account's secure channel to forward `DC01$`'s credentials to the real
DC. The goal: convince the DC to validate `DC01$`'s identity so the CA will
issue a certificate belonging to the Domain Controller.

### 4. The detection tell

The attack is visible at the network layer from two angles:

**Direction anomaly (`conn.log`):** `172.16.14.10` to `172.16.14.50:445`.
A CA or DC should never initiate SMB to a workstation. Any monitoring rule
that alerts on a server-class host appearing as `id.orig_h` in an SMB connection
to a non-server would have caught this.

**Identity anomaly (`ntlm.log`):** `DC01$` authenticating to a host named
`GHOSTJVSRGDNR`: a randomly generated machine account name, not a registered
server. The `server_nb_computer_name` field in `ntlm.log` on the DC01$ rows
exposes the rogue server's name directly.

`weird.log` adds a third signal: `netlogon_dce_rpc_auth_type=68` on every
relay attempt: Zeek flagging an unusual Netlogon authentication type on each
connection. Eight identical entries in 35 seconds.

## Key IOCs

| Artifact | Value |
|---|---|
| CVE | CVE-2026-54121 (Certighost) |
| Launching account | `a.novak` |
| Rogue machine account | `GHOSTJVSRGDNR$` |
| CA callback destination | `172.16.14.50:445` |
| CA authenticating as | `DC01$` |
| Rogue server name | `GHOSTJVSRGDNR` |
| Netlogon relay operations | `NetrServerReqChallenge`, `NetrServerAuthenticate3`, `NetrLogonGetCapabilities`, `NetrLogonSamLogonWithFlags` |
| Zeek anomaly | `netlogon_dce_rpc_auth_type=68` (`weird.log`) |

## Lessons learned

1. The default `ms-DS-MachineAccountQuota` of 10 means any domain user can
   create machine accounts. Setting it to 0 removes this attack vector entirely
   for environments that do not need user-created computer objects.

2. The CA callback is the detection opportunity. A CA or DC appearing as the
   *originator* of an outbound SMB connection to a workstation is a high-fidelity
   signal: benign AD CS enrollment always flows client to CA, never CA to client.

3. `dce_rpc.log` is underused. The Netlogon relay sequence
   (`NetrServerReqChallenge` to `NetrServerAuthenticate3` to `NetrLogonGetCapabilities`
   to `NetrLogonSamLogonWithFlags`) firing eight times in 35 seconds from a
   workstation IP is not normal domain controller behaviour. A threshold rule
   on this sequence from a non-DC source would catch the relay without tuning for
   the specific CVE.

4. Randomised machine account names (`GHOSTJVSRGDNR`) are a real-world artefact
   of automated exploit tooling. Hunting for computer accounts with names matching
   the pattern of PoC-generated names (random uppercase strings, 12–15 chars, no
   business context) is a cheap, high-value hunt.

## References

- [Kudelski Security - Certighost Advisory](https://kudelskisecurity.com/research/certighost)
- [CVE-2026-54121 - Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121)
- [Certighost PoC - GitHub](https://github.com/aniqfakhrul/CVE-2026-54121)
- [Technical Analysis by H0j3n Gist](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [MITRE ATT&CK T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
