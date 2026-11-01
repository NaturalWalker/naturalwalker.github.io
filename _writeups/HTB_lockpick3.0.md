---
title: "HTB Sherlock - Lockpick3.0"
date: 2026-11-01
platform: "Hack The Box"
category: "Malware Analysis"      
difficulty: "Hard"
points: 565
tags: [Malware analysis, Sherlock]
---

## Overview

>The threat actors of the Lockpick variant of Ransomware seem to have increased their skillset. Thankfully on this occasion they only hit a development, non production server. We require your assistance performing some reverse engineering of the payload in addition to some analysis of some relevant artifacts. Interestingly we can't find evidence of remote access so there is likely an insider threat.... Good luck!

**Tools used:** `Binary Ninja`, `CyberChef`, `strings`, `md5sum`

## Analysis
In the archive we are given 3 files
- ubuntu-client
- ubuntu-client-Snapshot2.vmem
- ubuntu-client-Snapshot2.vmsn

### Task 1 - Please confirm the file hash of the malware? (MD5)

<img width="397" height="39" alt="image" src="https://github.com/user-attachments/assets/683d2a16-bc71-4186-accd-33f9197f35c6" />

```
Answer: a2444b61b65be96fc2e65924dee8febd
```

### Task 2 - Please confirm the XOR string utilised by the attacker for obfuscation?
Looking at the code, in the main function we can see that the key is given by the user in arguments argv[1] and passes it to the function `sub_4029ca`. So the key is not stored in the malware.

<img width="694" height="367" alt="image" src="https://github.com/user-attachments/assets/f2410510-0911-4289-98d5-4a23fcceff04" />

Because we have a VMEM dump of the ubuntu client we can check if we can recover the key using the memory. Because we know that the malware is named "ubuntu-client" we can search for it in the memory.

I used a simple: 
```bash
strings ubuntu-client-Snapshot2.vmem | grep "ubuntu-client"
```
<img width="500" height="68" alt="image" src="https://github.com/user-attachments/assets/cab18438-f4ff-4629-90f4-0c4f34de3d3c" />

```
Answer: xGonnaGiveIt2Ya
```
### Task 3 - What is the API endpoint utilised to retrieve the key?
Looking at the code and references we can see two endpoints "/connect" and "/upload/".
The first one : "/connect" is the one we are looking for.

<img width="1058" height="598" alt="image" src="https://github.com/user-attachments/assets/2731b3b1-9c68-4bcb-89e7-63445f8c4a02" />


The url is stored in data_406020, and by using cross reference we can see it is using the XOR function "sub_4029ca" with the argv[1] key passed as parameter.
Both endpoints are appended with the data_406020 base URL.

<img width="1058" height="598" alt="image" src="https://github.com/user-attachments/assets/f89b9c08-50c2-4839-890b-8aafd8101343" />

<img width="1221" height="97" alt="image" src="https://github.com/user-attachments/assets/32530967-659b-4b28-843f-8fda25fd96d2" />

We can now use the previously found XOR key and data_406020

<img width="1545" height="498" alt="image" src="https://github.com/user-attachments/assets/7a63b119-6074-4f07-b324-c7807250eedf" />

```
Answer: hxxps[://]plankton-app-3qigq[.]ondigitalocean[.]app/connect
```
### Task 4 - What is the API endpoint utilised for upload of files?
Now the second endpoint is "/upload" we found earlier.

<img width="1114" height="629" alt="image" src="https://github.com/user-attachments/assets/dfd485b3-4441-484f-8338-441760343aec" />


It is also using data_406020 so we can just complete using the previously retrieved url. The file is sent with an HTTP PUT and an X-Filename header

<img width="733" height="135" alt="image" src="https://github.com/user-attachments/assets/ffb025b6-2bc1-4616-8579-972bb5b178f6" />

```
Answer: hxxps[://]plankton-app-3qigq[.]ondigitalocean[.]app/upload/
```
### Task 5 - What is the name of the service created by the malware?
The service name is not visible in the binary. Like the URL, it is stored in one of the seven strings that main function decrypts.
Looking at other call in the main function we can find more information on how the malware runs and reveal how the malware installs itself.

<img width="482" height="143" alt="image" src="https://github.com/user-attachments/assets/5929644e-9420-4349-a0ae-a2204a3b10e2" />


The creation of the persistence in sub_40380b receives argv[0], the malware own path and copies the binary.

<img width="918" height="605" alt="image" src="https://github.com/user-attachments/assets/ce527622-74fc-47f6-a41c-72eaf3aa1c0e" />

<img width="1227" height="604" alt="image" src="https://github.com/user-attachments/assets/ceee21d9-aaf2-46ab-b8b3-10965eff21b9" />


Decrypting the longest encrypted string with the same key reveals a complete systemd unit file:

<img width="1040" height="633" alt="image" src="https://github.com/user-attachments/assets/f1e12467-d933-44f8-9a83-dab38fd30e03" />


It then writes a systemd unit file and enables it with systemctl. As we can see the ExecStart passes the XOR key as an argument. Without it, the malware could not decrypt its strings after a reboot.

Looking at the last strings passed to the sub_4029ca function reveals the persistence mechanism. A systemd unit file and the commands to enable it at boot.

<img width="1068" height="514" alt="image" src="https://github.com/user-attachments/assets/d4d658c4-74ec-45f2-8965-49c84f9a1f4b" />

```
Answer: ubuntu_running.service
```
### Task 6 - What is the technique ID utilised by the attacker for persistence?

<img width="1409" height="476" alt="image" src="https://github.com/user-attachments/assets/e8ab9499-8f38-447f-8320-607d11392b12" />

The malware achieves persistence by registering a systemd service that relaunches it at boot. In MITRE ATT&CK this maps to :

```
Answer: T1543.002
```

## IOCs

| Type | Value |
|---|---|
| MD5 | `a2444b61b65be96fc2e65924dee8febd` |
| XOR key | `xGonnaGiveIt2Ya` |
| C2 domain | `plankton-app-3qigq[.]ondigitalocean[.]app` |
| Endpoints | `/connect`, `/upload/<id>` |
| Persistence | `/etc/systemd/system/ubuntu_running.service` |
| MITRE ATT&CK | T1543.002 |
