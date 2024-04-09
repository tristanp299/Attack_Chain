#### Attacks
- [[Overpass the Hash]]

It is possible to misuse this tool for lateral movement, but three requisites must be met. First, the user that authenticates to the target machine needs to be part of the Administrators local group. Second, the _ADMIN$_ share must be available, and third, File and Printer Sharing has to be turned on. Luckily for us, the last two requirements are already met as they are the default settings on modern Windows Server systems.

To execute the command remotely, PsExec performs the following tasks:

- Writes **psexesvc.exe** into the **C:\Windows** directory
    
- Creates and spawns a service on the remote host
    
- Runs the requested program/command as a child prpowerocess of **psexesvc.exe**
    
- ```./PsExec64.exe
    hostname
    whoami```
    ```