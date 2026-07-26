---
layout: post
title: "BlackEnergy v2: Memory Forensics of a Rootkit Infection"
date: 2026-07-20
categories: [memory-forensics]
tags: [volatility, rootkit, dll-injection, cyberdefenders]
---

*CyberDefenders · Endpoint Forensics · Memory Analysis · Medium difficulty · 8/8 flags*

Memory forensics investigation of a multinational corporation breach via the
BlackEnergy v2 rootkit: process injection, hidden DLL identification, and
kernel-mode driver analysis.

## At a glance

| | |
|---|---|
| Volatility profile | `WinXPSP2x86` |
| Running processes | 19 |
| Malicious process | `svchost.exe` PID 880 |
| Injected DLL | `msxml3r.dll` |
| DLL base address | `0x980000` |
| Rootkit driver | `str.sys` |

## Scenario

A multinational corporation suffered a targeted attack resulting in sensitive data
theft. The attack leveraged a previously unseen variant of BlackEnergy v2, a
sophisticated rootkit with documented use against critical infrastructure.

The task: analyse a raw memory dump of the compromised Windows XP machine
(`CYBERDEF-567078-20230213-171333.raw`) to determine the scope of infection — which
processes were abused, how the malware concealed itself, and what artifacts confirm
malicious activity.

## Tools

Volatility 3 · VirusTotal · `md5sum` / `sha256sum`

## MITRE ATT&CK mapping

| Tactic | ID | Technique | Evidence observed |
|---|---|---|---|
| Execution | [T1106](https://attack.mitre.org/techniques/T1106/) | Native API | `rootkit.exe` spawned `cmd.exe` (PID 1960) via Windows API; confirmed via `pstree` parent-child relationship |
| Privilege Escalation | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | DLL Injection | `msxml3r.dll` injected into `svchost.exe` PID 880; all three `ldrmodules` flags returned False, indicating a hidden/unlinked DLL |
| Defense Evasion | [T1014](https://attack.mitre.org/techniques/T1014/) | Rootkit | Kernel driver `str.sys` found at `C:\WINDOWS\system32\drivers\`; kernel-level component hides processes and files |
| Defense Evasion | [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | Masquerading: Match Legitimate Name | `msxml3r.dll` named to mimic legitimate `msxml3.dll` — one character apart, designed to evade cursory inspection |
| Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Malware uses mutant objects (`Zones*`, `RasPbFile`, `Wininet*`) within `svchost.exe` to enumerate and coordinate across processes |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Sensitive data theft confirmed per scenario brief; rootkit provided persistent access enabling exfiltration |

## Walkthrough

### 1. Profile identification and environment baseline

The first step with any memory dump is establishing the correct Volatility profile —
the wrong one returns garbage output. Running `imageinfo` (Vol2) or `windows.info`
(Vol3) suggested two candidates: `WinXPSP2x86` and `WinXPSP3x86`. The lab accepts
**`WinXPSP2x86`**.

```
vol -f CYBERDEF-567078-20230213-171333.raw windows.info
```

`pslist` gave a full process inventory. Counting only active processes (threads > 0,
no exit time) returned **19 running processes**. Two immediately stood out as
terminated but suspicious: `rootkit.exe` and `cmd.exe`.

```
vol -f CYBERDEF-567078-20230213-171333.raw windows.pslist
```

![Volatility windows.pslist output](/screenshots/1vol_windowspslist.png)

### 2. Suspicious process identification

`rootkit.exe` is self-evidently abnormal. `pstree` confirmed the parent-child
relationship: `rootkit.exe` spawned `cmd.exe` (PID 1960) — consistent with an attacker
dropping a rootkit and using it to launch a command shell. `psxview` further revealed
processes attempting to hide from the standard process list.

```
vol -f CYBERDEF-567078-20230213-171333.raw windows.pstree | less -S
```

![Process tree showing rootkit.exe spawning cmd.exe](/screenshots/2vol__childprocesses.png)

### 3. Code injection detection via malfind

`malfind` scans for memory regions that are executable, writable, and contain an MZ
header — the hallmarks of injected code rather than random data.

**`svchost.exe` (PID 880)** stood out clearly: the VAD entry showed
`PAGE_EXECUTE_READWRITE` protection and bytes beginning `4D 5A`, the MZ magic bytes of
a PE executable. Base address of the injected region: **`0x980000`**.

```
vol -f CYBERDEF-567078-20230213-171333.raw windows.malfind
```

![malfind output showing MZ header magic bytes](/screenshots/3vol_MZHeaderMagicBytes.png)

Dumping the injected region and submitting the hash to VirusTotal confirmed it as a
BlackEnergy variant — multiple vendors flagged it as malicious.

### 4. Hidden DLL and kernel driver artifacts

`ldrmodules` lists all modules loaded into a process and flags any unlinked from the
three Windows loader lists. A DLL with `InLoad=False`, `InInit=False`, `InMem=False`
is actively hiding itself.

```
vol -f CYBERDEF-567078-20230213-171333.raw windows.ldrmodules --pid 880
```

One entry returned all three as False: **`msxml3r.dll`**.

![ldrmodules output showing hidden msxml3r.dll](/screenshots/4vol_msxml3rDLL.png)

`windows.handles --pid 880` revealed an unusual file reference:
`C:\WINDOWS\system32\drivers\str.sys` — the kernel-mode component of BlackEnergy, used
to hide processes and files from the OS.

The raw output was noisy, so I filtered it:

```
vol -f CYBERDEF-567078-20230213-171333.raw windows.handles --pid 880 | grep File
```

![handles output showing str.sys driver reference](/screenshots/5vol_strSYS.png)

## Key IOCs

| Artifact | Value |
|---|---|
| Malware family | BlackEnergy v2 |
| Volatility profile | `WinXPSP2x86` |
| Malicious process | `rootkit.exe` |
| Injected process | `svchost.exe` PID 880 |
| Injected DLL | `msxml3r.dll` |
| DLL base address | `0x980000` |
| Rootkit driver | `C:\WINDOWS\system32\drivers\str.sys` |
| Spawned shell | `cmd.exe` PID 1960 (parent: `rootkit.exe`) |

## Lessons learned

1. `PAGE_EXECUTE_READWRITE` combined with an MZ header is a clear code injection
   indicator — legitimate DLLs do not load this way.

2. The `ldrmodules` InLoad/InInit/InMem flags are more reliable than filenames for
   identifying hidden modules.

3. BlackEnergy's kernel driver (`str.sys`) illustrates why memory forensics is
   essential. A rootkit operating at kernel level can hide itself from the OS entirely,
   making disk-based artifacts unreliable. Memory is the ground truth.

4. Plugin sequencing matters: `pslist` → `pstree` → `malfind` → `ldrmodules` →
   `handles` is a repeatable Windows memory triage workflow, covering process
   anomalies, injection, hidden modules, and file artifacts in a logical order.

## References

- [CyberDefenders — BlackEnergy Lab](https://cyberdefenders.org/blueteam-ctf-challenges/blackenergy/)
- [MITRE ATT&CK — BlackEnergy Malware (S0089)](https://attack.mitre.org/software/S0089/)
- [Volatility 3 command reference](https://hacktivity.fr/volatility-3-cheatsheet/)
- [VirusTotal](https://www.virustotal.com/)
