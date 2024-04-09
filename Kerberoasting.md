
Concept:

- When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.
- These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.
- The service ticket is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account.

- Example on Windows (w/ Rubeus):
    
    - In this section, we will abuse a service ticket and attempt to crack the password of the service account.
    - Set up:
        - Let's begin by connecting to CLIENT75 via RDP as jeff with the password HenchmanPutridBonbon11.
    - Start:
    - Use Rubeus  
        - Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user
        - `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
            - **kerberoast** -> technique
            - **hashes.kerberoast** -> the resulting TGS-REP hash
            - output -> 1 usr hash
    - Copy **hashes.kerberoast** to our Kali to crack
        - `cat hashes.kerberoast`
        - `hashcat --help | grep -i "Kerberos"`
        - `sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
        - output -> Strawberry1
- Example on Linux (w/ [[Impacket]])
    
    - Use _impacket-GetUserSPNs_  
        -Since our Kali machine is not joined to the domain, we also have to provide domain user credentials to obtain the TGS-REP hash
        - `sudo impacket-GetUserSPNs -request -dc-ip 192.168.200.70 corp.com/pete`
        - [Note]:
            - [`If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate or rdate to do so`]
    - Store the TGS-REP hash in a file named hashes.kerberoast2 and crack it
        - `sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
- This technique is immensely powerful if the domain contains high-privilege service accounts with weak passwords
    
- However, if the SPN runs in the context of a computer account, a managed service account,5 or a group-managed service account,6 the password will be randomly generated, complex, and 120 characters long, making cracking infeasible
    
- Same is true for the _krbtgt_ user account
    
    - acts as service account for the KDC
- Let's assume that we are performing an assessment and notice that we have GenericWrite or GenericAll permissions7 on another AD user account --> we could also set an SPN for the user,8 kerberoast the account, and crack the password hash in an attack named _targeted Kerberoasting_