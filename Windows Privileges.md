
-  SeBackupPrivilege
- SeAssignPrimaryToken
- SeLoadDriver
- SeDebug
- *SeImpersonatePrivilege*
	- Non-priv users with assigned privs
		- Enabled by default on:
			- Administrators group
			- LOCAL SERVICE account
			- NETWORK SERVICE account
			- SERVICE  account
	- Can be found in exploiting an IIS (Internet Information Service) web server
		- IIS runs as _LocalService_, _LocalSystem_, _NetworkService_, or cApplicationPoolIdentity
	- RPC or *named pipes*
		- Once a client connects to a named pipe, the server can leverage _SeImpersonatePrivilege_ to impersonate this client after capturing the authentication from the connection process.