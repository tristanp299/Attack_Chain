- *SharpHound*
	- data collection tool
	- We can compile it ourselves, use an already compiled executable, or use it as a PowerShell script
	- Ouput as a zipped json 

- Example:
	- Import module
		- `PS C:\Tools> Import-Module .\Sharphound.ps1`
	- We must first run **Invoke-BloodHound**.
		- `Get-Help Invoke-BloodHound`
		-`Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\TEMP\ -OutputPrefix "audit"`
			- ** -CollectionMethod** = describes the various collection methods.
			- **All** = all data
	- collected data location:
		`ls C:\Users\stephanie\Desktop\`
	-  Sharphound created the **bin** cache file to speed up data collection. This is not needed for our analysis and we can safely delete it.
- [Note]:
	- One thing to note is that SharpHound also supports _looping_, which means that the collector will run cyclical queries of our choosing over a period of time.