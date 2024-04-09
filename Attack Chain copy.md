https://wadcoms.github.io/
https://github.com/swisskyrepo/PayloadsAllTheThings
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- brutex
- [[SMB]]
- [[FTP]]
- [[Find_Found Login_Username_Password]]
- [[Found Hash]]
- [[Transferring Files]]
- [[Proxy Nmap]]

- AD
  - Get usernames ( from rpc, http etc..)
  -  Use kerbrute to identify valid users and check for Kerberos pre authentication for the users (getnpusers.py).
  - ` nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' `
  - Enumerate the open ports once again with the creds
  - bloodhound.py