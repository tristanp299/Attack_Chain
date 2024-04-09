` hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/demo3.rule --force `
  - ssh2john
  - keepass2john
    - ` keepass2john Database.kdbx > keepass.hash `

` smbclient \\\\192.168.239.43\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b `