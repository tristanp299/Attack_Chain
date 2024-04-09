-  *LSASS* (Local Security Authority Subsystem Service) memory space
	- Hashes are stored in LSASS
	- runs as SYSTEM (system process)
		- we need SYSTEM (or local administrator) perm
		- usually start our attack with a local privilege escalation
	- the data structures used to store the hashes in memory are not publicly documented, and they are also encrypted with an LSASS-stored key

- *Mimikatz* -> important note
		- [Due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed in the Antivirus Evasion Module instead. For example, execute Mimikatz directly from memory using an injector like PowerShell,4 or use a built-in tool like Task Manager to dump the entire LSASS process memory,5 move the dumped data to a helper machine, and then load the data into Mimikatz]

Example with **hashes**:
- Setup (Since the jeff domain user is a local administrator on CLIENT75, we are able to launch a PowerShell prompt with elevated privileges.)
- First, let's connect to this machine as jeff over RDP
	- `xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.200.75`
- Start a PowerShell session as Admin
- Start Mimikatz and enter **privilege::debug** to engage the *SeDebugPrivlege* privilege, which will allow us to interact with a process owned by another account.
	-`cd C:\Tools`
	- `.\mimikatz.exe`
	- `privilege::debug`
- Now we can run **sekurlsa::logonpasswords** to dump the credentials of all logged-on users with the *Sekurlsa* module
		- This should dump hashes for all users logged on to the current workstation or server, *including remote logins* like Remote Desktop sessions.
	- `sekurlsa::logonpasswords`

- [Note]
	- effective defensive technique to prevent tools such as Mimikatz from extracting hashes is to enable additional LSA Protection.10 The LSA includes the LSASS process. By setting a registry key, Windows prevents reading memory from this process.
		- Taught in **PEN-300** (OffSec's Evasion Techniques and Breaching Defenses course)

- Use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets. As already discussed, we know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS, and we can use Mimikatz to interact with and retrieve our own tickets as well as the tickets of other local users.

Example with **Tokens/Tickets**:
- Create and cache a service ticket.
	- Let's open a second PowerShell window and list the contents of the SMB share on WEB04 with UNC path \\web04.corp.com\backup.
		- `dir \\web04.corp.com\backup`
- Once we've executed the directory listing on the SMB share, we can use Mimikatz to show the tickets that are stored in memory by entering **sekurlsa::tickets**
	- `sekurlsa::tickets`
	- output --> a TGT and a TGS
	-  Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain.
	- Mimikatz can also export tickets to the hard drive and import tickets into LSASS

- *PKI* (Public Key Infrastructure)
	- Microsoft provides the AD role *AD CS* (*Active Directory Certificate Services*) to implement a PKI, which exchanges digital certificates between authenticated users and trusted resources
	- If a server is installed as a *CA* (*Certification Authority*), it can issue and revoke digital certificates (and much more)
	- These certificates may be marked as having a non-exportable private key for security reasons
	- If so, a private key associated with a certificate cannot be exported even with administrative privileges. However, there are various methods to export the certificate with the private key.
	- We can rely again on Mimikatz to accomplish this. The *crypto* module contains the capability to either patch the CryptoAPI18 function with **crypto::capi** or KeyIso20 service with **crypto::cng**, making non-exportable keys exportable.