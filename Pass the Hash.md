
- allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the user's plaintext password
- attacker connects to the victim using the _Server Message Block_ (SMB) protocol and
- [Note]:
    - This will only work for servers or services using NTLM authentication

Many third-party tools and frameworks use PtH to allow users to both authenticate and obtain code execution, including:

- [_PsExec_](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/) from Metasploit
- [_Passing-the-hash toolkit_](https://github.com/byt3bl33d3r/pth-toolkit)
- [_Impacket_](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py)

Most tools that are built to abuse PtH can be leveraged to start a Windows service (for example, cmd.exe or an instance of PowerShell) and communicate with it using [_Named Pipes_](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365590(v=vs.85).aspx). This is done using the [Service Control Manager](https://msdn.microsoft.com/en-us/library/windows/desktop/ms685150(v=vs.85).aspx) API.  
- Unless we want to gain remote code execution, PtH does not need to create a Windows service for any other usage, such as accessing an SMB share.

3 Requirements:

1. Requires an SMB connection through the firewall (commonly port 445)
2. The Windows File and Printer Sharing feature to be enabled
3. **ADMIN$** share to be available.
    - To establish a connection to this share, the attacker must present valid credentials with local administrative permissions.

- This type of lateral movement typically requires local administrative rights

Example (w/ _wmiexec_ from **Impacket suite**)  
- To demonstrate this, we can use _wmiexec_ from the [Impacket suite](https://github.com/fortra/impacket/tree/master) from our local Kali machine against the local administrator account on FILES04. We are going to invoke the command by passing the local Administrator hash that we gathered in a previous Module and then specifying the username along with the target IP.

- `/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.198.72`
    
- `hostname`
    
- `whoami`
    
- [Note]:
    
    - This method works for Active Directory domain accounts and the built-in local administrator account. However, due to the [2014 security update](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a), this technique can not be used to authenticate as any other local admin account.