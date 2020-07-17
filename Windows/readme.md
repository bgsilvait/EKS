EKS Windows Bootstrap Scripts

EKS Windows Bootstrap Scripts with DSR

usedata sample

```
<powershell>
iwr -o Start-EKSBootstrap.ps1 https://raw.githubusercontent.com/bgsilvait/EKS/master/Windows/Start-EKSBootstrap_116_DSR.ps1
[string]$EKSBootstrapScriptFile = "Start-EKSBootstrap.ps1"
[string]$cfn_signal = "$env:ProgramFiles\Amazon\cfn-bootstrap\cfn-signal.exe"
& $EKSBootstrapScriptFile -EKSClusterName Win-EKS-115  3>&1 4>&1 5>&1 6>&1
$LastError = if ($?) { 0 } else { $Error[0].Exception.HResult }
& $cfn_signal --exit-code=$LastError `
  --stack="Win-EKS-115001" `
  --resource="NodeGroup1" `
  --region=us-east-1
</powershell>
```
