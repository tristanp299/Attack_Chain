
-  chained compromise
	- attacker improves access through multiple higher-level accounts to reach a goal
- PowerView's *Find-LocalAdminAccess*
	- scans the network in an attempt to determine if our current user has administrative permissions
	-  relies on the OpenServiceW function --> connects to the Service Control Manager (SCM) on the target machines
	- SCM has database of installed services & drivers on Windows
	- PowerView will attempt to open this database with the SC_MANAGER_ALL_ACCESS access right, which require administrative privileges, 

Exampe:
	-  run **Find-LocalAdminAccess** against corp.com
		- supports parameters such as Computername and Credentials
		- `Find-LocalAdminAccess`

- Alternative ways to obtain information such as which user is logged in to which computer.
		-may be deprecated
	- *NetWkstaUserEnum*
		- requires admin priv
	- *NetSessionEnum*

- **Get-NetSession**
	- uses *NetWkstaUserEnum* and *NetSessionEnum *
	- `Get-NetSession -ComputerName files04 -Verbose`
	- `Get-NetSession -ComputerName web04 -Verbose`
	- `Get-NetSession -ComputerName client74`
	- According to the documentation for NetSessionEnum,3:1 there are five possible query levels: 0,1,2,10,502.
		-Level 0 only returns the name of the computer establishing the session. Levels 1 and 2 return more information but require administrative privileges.
		- This leaves us with Levels 10 and 502. Both should return information such as the name of the computer and name of the user establishing the connection. By default, PowerView uses query level 10 with NetSessionEnum, which should give us the information we are interested in.
		- The permissions required to enumerate sessions with NetSessionEnum are defined in the **SrvsvcSessionInfo** registry key, which is located in the **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity** hive.
- In order to view the permissions, we'll use the PowerShell **Get-Acl**
	-  This command will essentially retrieve the permissions for the object we define and print
	- `Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl`

- capability SID
	- unforgeable token of authority that grants a Windows component or a Universal Windows Application access to various resources

- Enumerate OS
	- **Net-GetComputer**
		- `Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`
- Unable to change registry hive
- *PsLoggedOn* application
	-  will enumerate the registry keys under **HKEY_USERS** to retrieve the security identifiers (SID) of logged-in users and convert the SIDs to usernames.
		- from *SysInternals Suite*
	- Also uses the NetSessionEnum API 
	-  Relies on the Remote Registry service in order to scan the associated key
		- Disabled by default
	-  If it is enabled, the service will stop after ten minutes of inactivity to save resources, but it will re-enable (with an automatic trigger) once we connect with PsLoggedOn
	- Located in: **C:\Tools\PSTools**
	- Run: 
		- `.\PsLoggedon.exe \\files04`
		- `.\PsLoggedon.exwe \\web04`
			- May be false positive (dont know if Remote Registry service is running)
		- `.\PsLoggedon.exe \\client74`