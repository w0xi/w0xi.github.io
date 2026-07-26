---
layout: post
title: "PacketMaze: Insider Threat Network Investigation"
date: 2026-04-19
categories: [network-forensics]
tags: [wireshark, exiftool, pcap, insider-threat, cyberdefenders]
---

*CyberDefenders · Network Forensics · Insider Threat · Medium difficulty · 11/11 flags*

Multi-protocol PCAP investigation of a suspected insider: correlating FTP credential
exposure, EXIF metadata extraction, TLS session analysis, and encrypted communication
patterns to build an evidence-backed behavioural timeline.

## At a glance

| | |
|---|---|
| Subject IP | `192.168.1.26` |
| Subject MAC | `c8:09:a8:57:47:93` |
| FTP password | `AfricaCTF2021` (plaintext) |
| File exfiltrated | `20210429_152157.jpg` |
| Device (EXIF) | LM-Q725K (LG Q7+) |
| ProtonMail contact | 2021-04-30 01:04 UTC |

## Scenario

A company's internal server was flagged for unusual network activity, with multiple
outbound connections to an unknown external IP. Initial analysis suggested possible
data exfiltration.

The capture (`UNODC-GPC-001-003-JohnDoe-NetworkCapture-2021-04-29.pcapng`) covers the
subject's activity across FTP, DNS, TLS, and UDP. The investigation requires
correlating artifacts across all of them: file transfers, encrypted communications,
DNS lookups, and image metadata to build a complete picture of behaviour and intent.

## Tools

Wireshark · exiftool · MAC lookup (dnschecker) · Statistics → Conversations ·
Statistics → Protocol Hierarchy · TCP stream extraction

## MITRE ATT&CK mapping

| Tactic | ID | Technique | Evidence observed |
|---|---|---|---|
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Subject authenticated to external FTP server using plaintext credentials: a legitimate user abusing access for unauthorised data transfer |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Photo `20210429_152157.jpg` transferred to external FTP server; EXIF metadata confirmed camera model LM-Q725K (LG Q7+), establishing device attribution |
| Exfiltration | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted Protocol | File uploaded via FTP `STOR` in plaintext; credentials and file content fully visible in the PCAP |
| Defense Evasion | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Subject connected to ProtonMail over TLS 1.3, end-to-end encrypted email to avoid content monitoring |
| Defense Evasion | [T1564](https://attack.mitre.org/techniques/T1564/) | Hide Artifacts | Non-standard `/ftp` directory created on the FTP server April 20 at 17:53, pre-planned staging infrastructure, nine days before the monitored session |
| Reconnaissance | [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | DNS lookup for `www.7-zip.org` (packet 15174) shows the subject researching compression tools, consistent with data staging preparation |

## Walkthrough

### 1. Subject identification and FTP credential exposure

Starting with **Statistics → Protocol Hierarchy** gave an immediate overview of
protocols present: FTP, FTP-DATA, DNS, TLS, HTTP. A mix of plaintext and encrypted
activity, suggesting multiple investigative angles.

Filtering for FTP exposed the first critical finding: FTP transmits credentials in
plaintext. Packet 500 contained the subject's authentication with the password
**`AfricaCTF2021`** fully visible, no encryption.

```
ftp
```

The subject's IP was identified as **`192.168.1.26`** and MAC as
**`c8:09:a8:57:47:93`** from the Ethernet layer of any originating packet.

![Wireshark showing plaintext FTP password](/screenshots/lab2_packetmaze/lab2_wireshark_ftpPASSWORD_1.png)

### 2. DNS analysis and behavioural context

Filtering for DNS and cross-referencing via **Statistics → Conversations → IPv6**
revealed the DNS server's IPv6 address: `fe80::c80b:adff:feaa:1db7`. This required
pivoting from the subject's IPv4 address to its MAC, then matching that MAC in the
IPv6 tab: a multi-step correlation testing understanding of Layer 2 and Layer 3
addressing.

```
udp && ip.src == 192.168.1.26 && ip.dst == 24.39.217.246
```

Jumping to packet 15174 revealed a DNS query for **`www.7-zip.org`**. In the context
of an insider investigation, a subject researching compression tools is behaviourally
significant and consistent with data staging.

```
frame.number == 15174
```

Packet 27300 resolved to `dfir.science`.

![Wireshark DNS query for 7-zip.org](/screenshots/lab2_packetmaze/lab2_wireshark_7zipURL_2.png)

### 3. File transfer and EXIF metadata extraction

Filtering for FTP-DATA showed file transfer activity. Searching packet bytes for
`20210429_152157.jpg` identified a `STOR` command in frame 7070, the subject
uploading a photo to an external FTP server.

```
ftp-data
```

Following TCP stream 14 and saving the raw bytes extracted the actual image file.
Running exiftool on it revealed camera metadata: model **LM-Q725K**, an LG Q7+
smartphone.

```
exiftool 20210429_152157.jpg
```

![exiftool output showing camera model](/screenshots/lab2_packetmaze/lab2_wireshark_cameraMODEL_3.png)

The FTP directory listing (TCP streams 11–12) showed a non-standard `/ftp` directory
created **April 20 at 17:53** which is nine days prior, indicating pre-planned staging
infrastructure.

![FTP directory listing showing staging folder](/screenshots/lab2_packetmaze/lab2_wireshark_ftpFOLDER_4.png)

### 4. ProtonMail, TLS session analysis, and encrypted communication mapping

```
dns.flags.response == 1
```

This revealed `mail.protonmail.com` and its IP address `185.70.41.130`.

![DNS response resolving protonmail](/screenshots/lab2_packetmaze/lab2_wireshark_protonmail_5A.png)

![ProtonMail IP address in Wireshark](/screenshots/lab2_packetmaze/lab2_wireshark_protonmail_5B.png)

Two TLS questions required locating specific sessions: one by session ID, one by
destination domain. For the session ID, a `tls` filter located
`da4a0000342e4b73...`, returning frame 26906; the reassembled PDU in frame 26913
contained the full handshake and server certificate public key under Server Key
Exchange.

For ProtonMail:

```
tls.handshake.type == 1 && tls.handshake.extensions_server_name == "protonmail.com"
```

The first Client Hello, at **2021-04-30 01:04:29 UTC**, contained the TLS 1.3 client
random: `24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70`.

![TLS client random in Wireshark](/screenshots/lab2_packetmaze/lab2_wireshark_randomTLSkey_6.png)

### 5. FTP server attribution via MAC lookup

Filtering FTP-DATA packets revealed the FTP server MAC address:
**`08:00:27:a6:1f:86`**. Submitting this to dnschecker.org's MAC lookup returned OUI
registration in the **United States**: a VirtualBox NIC, indicating a virtualised
server.

![MAC lookup result showing US registration](/screenshots/lab2_packetmaze/lab2_wireshark_countryUS_7.png)

## Key findings

| Artifact | Value |
|---|---|
| Subject IP | `192.168.1.26` |
| Subject MAC | `c8:09:a8:57:47:93` |
| FTP credential | `AfricaCTF2021` (plaintext) |
| File exfiltrated | `20210429_152157.jpg` |
| Device attributed | LM-Q725K (LG Q7+) |
| FTP server origin | United States (MAC `08:00:27:a6:1f:86`, VirtualBox OUI) |
| ProtonMail contact | 2021-04-30 01:04:29 UTC |
| Staging folder created | April 20 at 17:53 |

## Lessons learned

1. FTP exposes everything in plaintext: credentials, filenames, and full file
   content. SFTP or FTPS are the correct alternatives, and their absence here is
   itself a finding.

2. EXIF metadata extracted from an image provides device attribution that text-based
   evidence cannot. Camera model, GPS coordinates (if enabled), and embedded timestamps
   are legally defensible artifacts; knowing how to extract and interpret them with
   exiftool is a genuinely useful skill.

3. Layer 2 and Layer 3 correlation is a real investigative technique, not a lab
   curiosity. Pivoting IPv4 → MAC → IPv6 was the only route to the DNS server's
   address.

4. Behavioural context matters as much as technical artifacts. ProtonMail use, 7-zip
   DNS lookups, pre-staged FTP directories, and photo exfiltration together create a
   coherent insider threat narrative. None is individually conclusive; together they
   tell a clear story.

## References

- [CyberDefenders PacketMaze Lab](https://cyberdefenders.org/blueteam-ctf-challenges/packetmaze/)
- [MITRE ATT&CK Exfiltration Over Unencrypted Protocol (T1048.003)](https://attack.mitre.org/techniques/T1048/003/)
- [exiftool documentation](https://exiftool.org/)
- [MAC address lookup — dnschecker.org](https://dnschecker.org/mac-lookup.php)
- [Wireshark TLS analysis guide](https://wiki.wireshark.org/TLS)
