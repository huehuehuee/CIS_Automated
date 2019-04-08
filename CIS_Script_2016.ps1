Write-Output "CIS Windows Server 2016 RTM Release 1607 V1.1.0`n"

function audit-check {
    param(
      [string]$testName,
      [string]$pathName,
      [string]$keyName,
      [string]$operator,
      [int]$successCondition 
    )
    $queryLine = Get-ItemProperty -Path $pathName -Name $keyName -ErrorAction SilentlyContinue -ErrorVariable ProcessError | findstr -i $keyName
    if($ProcessError){
      Write-Host "$testName [Fail]`n$keyName Value not found, do a manual check`n" -ForegroundColor Red
    }
    else {
      $keyValue = $queryLine.Split(" ")[-1]
      if($operator.Equals("eq")){
        if([int]$keyValue -eq $successCondition){
          Write-Host "$testName [Pass]`n" -ForegroundColor Green
        }
        else {
          Write-Host "$testName [Fail]`n$queryLine`n" -ForegroundColor Red
        }
      }
      elseif ($operator.Equals("ne")){
        if([int]$keyValue -ne $successCondition){
          Write-Host "$testName [Pass]`n" -ForegroundColor Green
        }
        else {
          Write-Host "$testName [Fail]`n$queryLine`n" -ForegroundColor Red
        }
      }
      elseif ($operator.Equals("gt")) {
        if([int]$keyValue -gt $successCondition){
          Write-Host "$testName [Pass]`n" -ForegroundColor Green
        }
        else {
          Write-Host "$testName [Fail]`n$queryLine`n" -ForegroundColor Red
        }
      }
      elseif ($operator.Equals("ge")) {
        if([int]$keyValue -ge $successCondition){
          Write-Host "$testName [Pass]`n" -ForegroundColor Green
        }
        else {
          Write-Host "$testName [Fail]`n$queryLine`n" -ForegroundColor Red
        }
      }
      elseif ($operator.Equals("lt")) {
        if([int]$keyValue -lt $successCondition){
          Write-Host "$testName [Pass]`n" -ForegroundColor Green
        }
        else {
          Write-Host "$testName [Fail]`n$queryLine`n" -ForegroundColor Red
        }
      }
      elseif ($operator.Equals("le")){
        if([int]$keyValue -le $successCondition){
          Write-Host "$testName [Pass]`n" -ForegroundColor Green
        }
        else {
          Write-Host "$testName [Fail]`n$queryLine`n" -ForegroundColor Red
        }
      }
      else {
        Write-Host "Error in choosing operator`n" -ForegroundColor Red
      }

    }
}
# 2.2.36 (L2) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)
Write-Host "Unable to Automate. Please verify at Group Policy: Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Log on as a batch job `nConfiguration: Administrators`n" -ForegroundColor Red
#2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
audit-check -testName "2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)" -pathName "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -keyName "CachedLogonsCount" -successCondition 4 -operator "le"

#2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
audit-check -testName "2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'" -pathName "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -keyName "DisableDomainCreds" -successCondition 1 -operator "eq"

#18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled'
audit-check -testName "18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled" -pathName "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -keyName "AllowOnlineTips" -successCondition 1 -operator "eq"

# 18.4.5 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes
audit-check -testName "18.4.5 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes" -pathName "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -keyName "KeepAliveTime" -successCondition 300000 -operator "eq"

# 18.4.7 (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
audit-check -testName "18.4.7 (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'" -pathName "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -keyName "PerformRouterDiscovery" -successCondition 0 -operator "eq"

# 18.4.10 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
audit-check -testName "18.4.10 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'" -pathName "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -keyName "TcpMaxDataRetransmissions" -successCondition 3 -operator "eq"

# 18.4.11 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
audit-check -testName "18.4.11 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'" -pathName "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -keyName "TcpMaxDataRetransmissions" -successCondition 3 -operator "eq"

# 18.5.5.1 (L2) Ensure 'Enable Font Providers' is set to 'Disabled' 
audit-check -testName "18.5.5.1 (L2) Ensure 'Enable Font Providers' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -keyName "EnableFontProviders" -successCondition 0 -operator "eq"

# 18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' || 4 different keys
audit-check "18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'|| Key: AllowLLTDIOOnDomain" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "AllowLLTDIOOnDomain" -successCondition 0 -operator "eq"
audit-check "18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'|| Key: AllowLLTDIOOnPublicNet" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "AllowLLTDIOOnPublicNet" -successCondition 0 -operator "eq"
audit-check "18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'|| Key: EnableLLTDIO" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "EnableLLTDIO" -successCondition 0 -operator "eq"
audit-check "18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'|| Key: ProhibitLLTDIOOnPrivateNet" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "ProhibitLLTDIOOnPrivateNet" -successCondition 0 -operator "eq"

# 18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled' || 4 different keys
audit-check "18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'|| Key: AllowRspndrOnDomain" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "AllowRspndrOnDomain" -successCondition 0 -operator "eq"
audit-check "18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'|| Key: AllowRspndrOnPublicNet" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "AllowRspndrOnPublicNet" -successCondition 0 -operator "eq"
audit-check "18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'|| Key: EnableRspndr" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "EnableRspndr" -successCondition 0 -operator "eq"
audit-check "18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'|| Key: ProhibitRspndrOnPrivateNet" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -keyName "ProhibitRspndrOnPrivateNet" -successCondition 0 -operator "eq"

# 18.5.10.2 (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
audit-check "18.5.10.2 (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -keyName "Disabled" -successCondition 1 -operator "eq"

# 18.5.19.2.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')
audit-check "18.5.19.2.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')" -pathName "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -keyName "DisabledComponents" -successCondition 255 -operator "eq"

# 18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' || 5 different keys
audit-check "18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'|| Key: EnableRegistrars" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -keyName "EnableRegistrars" -successCondition 0 -operator "eq"
audit-check "18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'|| Key: DisableUPnPRegistrar" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -keyName "DisableUPnPRegistrar" -successCondition 0 -operator "eq"
audit-check "18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'|| Key: DisableInBand802DOT11Registrar" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -keyName "DisableInBand802DOT11Registrar" -successCondition 0 -operator "eq"
audit-check "18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'|| Key: DisableFlashConfigRegistrar" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -keyName "DisableFlashConfigRegistrar" -successCondition 0 -operator "eq"
audit-check "18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'|| Key: DisableWPDRegistrar" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -keyName "DisableWPDRegistrar" -successCondition 0 -operator "eq"

# 18.5.20.2 (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'
audit-check "18.5.20.2 (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -keyName "DisableWcnUi" -successCondition 1 -operator "eq"

# 18.5.21.2 (L2) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'
audit-check "18.5.21.2 (L2) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -keyName "fBlockNonDomain" -successCondition 1 -operator "eq"

# 18.8.22.1.2 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
audit-check -testName "18.8.22.1.2 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -keyName "PreventHandwritingDataSharing" -successCondition 1 -operator "eq"

# 18.8.22.1.3 (L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
audit-check -testName "18.8.22.1.3 (L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -keyName "PreventHandwritingErrorReports" -successCondition 1 -operator "eq"

# 18.8.22.1.4 (L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
audit-check -testName "18.8.22.1.4 (L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -keyName "ExitOnMSICW" -successCondition 1 -operator "eq"

# 18.8.22.1.7 (L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
audit-check -testName "18.8.22.1.7 (L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -keyName "NoRegistration" -successCondition 1 -operator "eq"

# 18.8.22.1.8 (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
audit-check -testName "18.8.22.1.8 (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -keyName "DisableContentFileUpdates" -successCondition 1 -operator "eq"

# 18.8.22.1.9 (L2) Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
audit-check -testName "18.8.22.1.9 (L2) Ensure 'Turn off the `"Order Prints`" picture task' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -keyName "NoOnlinePrintsWizard" -successCondition 1 -operator "eq"

# 18.8.22.1.10 (L2) Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
audit-check -testName "18.8.22.1.10 (L2) Ensure 'Turn off the `"Publish to Web`" task for files and folders' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -keyName "NoPublishingWizard" -successCondition 1 -operator "eq"

# 18.8.22.1.11 (L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
audit-check -testName "18.8.22.1.11 (L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -keyName "CEIP" -successCondition 2 -operator "eq"

# 18.8.22.1.12 (L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
audit-check -testName "18.8.22.1.12 (L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -keyName "CEIPEnable" -successCondition 0 -operator "eq"

# 18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
audit-check -testName "18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled' || Path: Windows Error Reporting Key: Disabled" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -keyName "Disabled" -successCondition 1 -operator "eq"
audit-check -testName "18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled' || Path: PCHealth\ErrorReporting Key: DoReport" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -keyName "DoReport" -successCondition 0 -operator "eq"

# 18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
audit-check -testName "18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic' || Key: DevicePKInitBehavior" -pathName "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -keyName "DevicePKInitBehavior" -successCondition 0 -operator "eq"
audit-check -testName "18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic' || Key: DevicePKInitEnabled" -pathName "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -keyName "DevicePKInitEnabled" -successCondition 1 -operator "eq"

# 18.8.26.1 (L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
audit-check -testName "18.8.26.1 (L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -keyName "BlockUserInputMethodsForSignIn" -successCondition 1 -operator "eq"

# 18.8.33.6.1 (L2) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'
audit-check -testName "18.8.33.6.1 (L2) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -keyName "DCSettingIndex" -successCondition 0 -operator "eq"

# 18.8.33.6.2 (L2) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'
audit-check -testName "18.8.33.6.2 (L2) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -keyName "ACSettingIndex" -successCondition 0 -operator "eq"

# 18.8.36.2 (L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only)
audit-check -testName "18.8.36.2 (L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only)" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -keyName "RestrictRemoteClients" -successCondition 1 -operator "eq"

# 18.8.44.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
audit-check -testName "18.8.44.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -keyName "DisableQueryRemoteServer" -successCondition 0 -operator "eq"

# 18.8.44.11.1 (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
audit-check -testName "18.8.44.11.1 (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -keyName "ScenarioExecutionEnabled" -successCondition 0 -operator "eq"

# 18.8.46.1 (L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'
audit-check -testName "18.8.46.1 (L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo" -keyName "DisabledByGroupPolicy" -successCondition 1 -operator "eq"

# 18.8.49.1.1 (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'
audit-check -testName "18.8.49.1.1 (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -keyName "Enabled" -successCondition 1 -operator "eq"

# 18.8.49.1.2 (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)
audit-check -testName "18.8.49.1.2 (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -keyName "Enabled"  -successCondition 0 -operator "eq"

# 18.9.4.1 (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'
audit-check -testName "18.9.4.1 (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -keyName "AllowSharedLocalAppData" -successCondition 0 -operator "eq"

# 18.9.12.1 (L2) Ensure 'Allow Use of Camera' is set to 'Disabled'
audit-check -testName "18.9.12.1 (L2) Ensure 'Allow Use of Camera' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -keyName "AllowCamera" -successCondition 0 -operator "eq"

# 18.9.16.2 (L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'
audit-check -testName "18.9.16.2 (L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -keyName "DisableEnterpriseAuthProxy" -successCondition 1 -operator "eq"

# 18.9.39.2 (L2) Ensure 'Turn off location' is set to 'Enabled'
audit-check -testName "18.9.39.2 (L2) Ensure 'Turn off location' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -keyName "DisableLocation" -successCondition 1 -operator "eq"

# 18.9.43.1 (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
audit-check -testName "18.9.43.1 (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -keyName "AllowMessageSync" -successCondition 0 -operator "eq"

# 18.9.58.3.2.1 (L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'
audit-check -testName "18.9.58.3.2.1 (L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -keyName "fSingleSessionPerUser" -successCondition 1 -operator "eq"

# 18.9.58.3.3.1 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'
audit-check -testName "18.9.58.3.3.1 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -keyName "fDisableCcm" -successCondition 1 -operator "eq"

# 18.9.58.3.3.3 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
audit-check -testName "18.9.58.3.3.3 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -keyName "fDisableLPT" -successCondition 1 -operator "eq"

# 18.9.58.3.3.4 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
audit-check -testName "18.9.58.3.3.4 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -keyName "fDisablePNPRedir" -successCondition 1 -operator "eq"

# 18.9.58.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'
audit-check -testName "18.9.58.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -keyName "MaxIdleTime" -successCondition 900000 -operator "le"

# 18.9.58.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'
audit-check -testName "18.9.58.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -keyName "MaxDisconnectionTime" -successCondition 60000 -operator "le"

# 18.9.60.2 (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'
audit-check "18.9.60.2 (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -keyName "AllowCloudSearch" -successCondition 0 -operator "eq"

# 18.9.65.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
audit-check "18.9.65.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -keyName "NoGenTicket" -successCondition 1 -operator "eq"

# 18.9.76.3.2 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'
audit-check "18.9.76.3.2 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -keyName "SpynetReporting" -successCondition 0 -operator "eq"
Write-Host "If registry entry not found, the policy is in effect" -ForegroundColor Red

# 18.9.76.9.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled'
audit-check "18.9.76.9.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -keyName "DisableGenericRePorts" -successCondition 1 -operator "eq"

# 18.9.84.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
audit-check "18.9.84.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -keyName "AllowSuggestedAppsInWindowsInkWorkspace" -successCondition 0 -operator "eq"

# 18.9.85.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'
audit-check "18.9.85.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -keyName "SafeForScripting" -successCondition 0 -operator "eq"

# 18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'
audit-check "18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -keyName "AllowAutoConfig" -successCondition 0 -operator "eq"

# 18.9.98.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'
audit-check "18.9.98.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'" -pathName "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -keyName "AllowRemoteShellAccess" -successCondition 0 -operator "eq"

Write-Host "The next four checks requires retrieval of user SID. Unable to automate without context?"
# 19.6.5.1.1 (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
Write-Host "Manual check for: 19.6.5.1.1 (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'" -ForegroundColor Red

# 19.7.7.3 (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'
Write-Host "Manual check for: 19.7.7.3 (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled''" -ForegroundColor Red

# 19.7.7.4 (L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'
Write-Host "Manual check for: 19.7.7.4 (L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'" -ForegroundColor Red

# 19.7.44.2.1 (L2) Ensure 'Prevent Codec Download' is set to 'Enabled'
Write-Host "Manual check for: 19.7.44.2.1 (L2) Ensure 'Prevent Codec Download' is set to 'Enabled'" -ForegroundColor Red
