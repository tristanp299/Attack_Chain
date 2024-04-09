
- **PowerView**
	- PowerShell script
	- Enumeration 
	- Installed:
		- **C\Tools**
	- Import to memory:
		- `powershell -ep bypass`
		- `PS C:\Tools> Import-Module .\PowerView.ps1
`
	- All commands:
		- [https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/active-directory-introduction-and-enumeration/active-directory-manual-enumeration/ad-enumeration-with-powerview#fn1]
	- also uses .NET classes to obtain the required LDAP path and uses it to communicate with AD

Example:
	- **Get-NetDomain**
		- Domain info
		- `Get-NetDomain`
	- **Get-Netuser**
			- list all users
		- `Get-NetUser | select cn`
		- `Get-NetUser | select cn,pwdlastset,lastlogon`
	- **Get-NetGroup**
		- `Get-NetGroup | select cn`
		- `Get-NetGroup "Sales Department" | select member`
