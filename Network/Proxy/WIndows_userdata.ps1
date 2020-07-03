<powershell>
$DefaultConnectionReg = "46,00,00,00,0b,00,00,00,03,00,00,00,30,00,00,00,73,71,75,69,64,6e,61,74,2d,61,76,2e,6d,61,72,6b,65,74,69,6e,74,65,6c,6c,69,67,65,6e,63,65,2e,73,70,67,6c,6f,62,61,6c,2e,63,6f,6d,3a,33,31,32,38,87,00,00,00,31,37,32,2e,32,30,2e,2a,3b,6c,6f,63,61,6c,68,6f,73,74,3b,31,32,37,2e,30,2e,30,2e,31,3b,31,30,2e,32,31,2e,36,34,2e,2a,3b,31,30,2e,2a,3b,2a,2e,73,33,2e,61,6d,61,7a,6f,6e,61,77,73,2e,63,6f,6d,3b,2a,2e,73,33,2e,75,73,2d,65,61,73,74,2d,31,2e,61,6d,61,7a,6f,6e,61,77,73,2e,63,6f,6d,3b,31,36,39,2e,32,35,34,2e,31,36,39,2e,32,35,34,3b,2a,2e,69,6e,74,65,72,6e,61,6c,3b,2a,2e,6d,6b,74,69,6e,74,2e,67,6c,6f,62,61,6c,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00"
$SavedLegacyReg = "46,00,00,00,0b,00,00,00,03,00,00,00,30,00,00,00,73,71,75,69,64,6e,61,74,2d,61,76,2e,6d,61,72,6b,65,74,69,6e,74,65,6c,6c,69,67,65,6e,63,65,2e,73,70,67,6c,6f,62,61,6c,2e,63,6f,6d,3a,33,31,32,38,87,00,00,00,31,37,32,2e,32,30,2e,2a,3b,6c,6f,63,61,6c,68,6f,73,74,3b,31,32,37,2e,30,2e,30,2e,31,3b,31,30,2e,32,31,2e,36,34,2e,2a,3b,31,30,2e,2a,3b,2a,2e,73,33,2e,61,6d,61,7a,6f,6e,61,77,73,2e,63,6f,6d,3b,2a,2e,73,33,2e,75,73,2d,65,61,73,74,2d,31,2e,61,6d,61,7a,6f,6e,61,77,73,2e,63,6f,6d,3b,31,36,39,2e,32,35,34,2e,31,36,39,2e,32,35,34,3b,2a,2e,69,6e,74,65,72,6e,61,6c,3b,2a,2e,6d,6b,74,69,6e,74,2e,67,6c,6f,62,61,6c,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00"
$SID = (Get-WmiObject win32_useraccount -Filter "name = 'administrator'" | Select SID).SID
$RegPath = 'Microsoft.PowerShell.Core\Registry::HKEY_USERS\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$RegPath1   = 'Microsoft.PowerShell.Core\Registry::HKEY_USERS\' + $SID + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$AttrName  = "DefaultConnectionSettings"
$AttrName1  = "SavedLegacySettings"
$hexified = $DefaultConnectionReg.Split(',') | % { "0x$_"}
$hexified1 = $SavedLegacyReg.Split(',') | % { "0x$_"}
Set-ItemProperty -Path $RegPath -Name $AttrName -Value ([byte[]]$hexified)
Set-ItemProperty -Path $RegPath -Name $AttrName1  -Value ([byte[]]$hexified1)
Set-ItemProperty -Path $RegPath1 -Name $AttrName -Value ([byte[]]$hexified)
Set-ItemProperty -Path $RegPath1 -Name $AttrName1  -Value ([byte[]]$hexified1)
[Environment]::SetEnvironmentVariable("HTTP_PROXY", "http://<PROXY_IP/DNS>:<PROXY_PORT>", [EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://<PROXY_IP/DNS>:<PROXY_PORT>", [EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable("NO_PROXY", "172.20.0.0/16,localhost,127.0.0.1,10.164.92.0/23,100.64.0.0/16,.s3.amazonaws.com,.s3.us-east-1.amazonaws.com,169.254.169.254,.internal", [EnvironmentVariableTarget]::Machine)
restart-service *docker*
[string]$EKSBinDir = "$env:ProgramFiles\Amazon\EKS"
[string]$EKSBootstrapScriptName = 'Start-EKSBootstrap.ps1'
[string]$EKSBootstrapScriptFile = "$EKSBinDir\$EKSBootstrapScriptName"
[string]$cfn_signal = "$env:ProgramFiles\Amazon\cfn-bootstrap\cfn-signal.exe"
& $EKSBootstrapScriptFile -EKSClusterName <CLUSTER-NAME>  3>&1 4>&1 5>&1 6>&1
$LastError = if ($?) { 0 } else { $Error[0].Exception.HResult }
& $cfn_signal --exit-code=$LastError `
  --stack="<STACK>" `
  --resource="NodeGroup" `
  --region=us-east-1
</powershell>
