# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

<#
.SYNOPSIS
EKS bootstrap script. Should maintain close parity with https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh
.PARAMETER EKSClusterName
Specifies the EKS cluster name which this worker node to be joined.
.PARAMETER KubeletExtraArgs
Specifies the extra arguments for kubelet.
.PARAMETER Endpoint
Specifies the EKS cluster endpoint(optional). Default is production endpoint.
.PARAMETER APIServerEndpoint
The EKS cluster API Server endpoint(optional). Only valid when used with -Base64ClusterCA. Bypasses calling "Get-EKSCluster".
.PARAMETER Base64ClusterCA
The base64 encoded cluster CA content(optional). Only valid when used with -APIServerEndpoint. Bypasses calling "Get-EKSCluster".
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$EKSClusterName,
  [string]$KubeletExtraArgs,
  [string]$Endpoint,
  [string]$APIServerEndpoint,
  [string]$Base64ClusterCA
)

$ErrorActionPreference = 'STOP'
Function Get-EKSPauseImage {
  # ECR Pause image URI
  # Keeping this function in case additional logic is needed to get the pause image in the future. 
  $PauseImageUri = 'amazonaws.com/eks/pause-windows:latest'
  return $PauseImageUri
}


#Arguments are added, deprecated, and removed with each version, this tracks arguments that are incompatible across versions. 
#At this point, there’s no difference between 1.14 and 1.15 arguments. In future, this can be used for version specific arguments 
Function Get-VersionArguments {
  #This parses the version (xx) from kubelet's version "Kubernetes v1.xx.yy-eks-******"
  $kubeletVersionCmd = "& `"$Kubelet`" --version"
  $versionID = (Invoke-Expression -Command $kubeletVersionCmd).Split('.')[1]
  [string]$versionArgs
  switch ($versionID) {
    "14" { $versionArgs = ""}
    "15" { $versionArgs = "" }
    "16" { $versionArgs = "" }
    Default { $versionArgs = "" }
  }
  $versionArgs = [string]::Join(' ', $versionArgs)
  return $versionArgs
}


[string]$EKSBinDir = "$env:ProgramFiles\Amazon\EKS"
[string]$EKSDataDir = "$env:ProgramData\Amazon\EKS"
[string]$CNIBinDir = "$EKSBinDir\cni"
[string]$CNIConfigDir = "$EKSDataDir\cni\config"
[string]$IAMAuthenticator = "$EKSBinDir\aws-iam-authenticator.exe"
[string]$EKSClusterCACertFile = "$EKSDataDir\cluster_ca.crt"

[string]$KubernetesBinDir = "$env:ProgramFiles\kubernetes"
[string]$KubernetesDataDir = "$env:ProgramData\kubernetes"
[string]$Kubelet = "$KubernetesBinDir\kubelet.exe"
[string]$Kubeproxy = "$KubernetesBinDir\kube-proxy.exe"

# KUBECONFIG environment variable is set by Install-EKSWorkerNode.ps1
[string]$KubeConfigFile = [System.Environment]::GetEnvironmentVariable('KUBECONFIG', 'Machine')

# Kubelet configuration file
[string] $KubeletConfigFile = "$KubernetesDataDir\kubelet-config.json"

[string]$StartupTaskName = "EKS Windows startup task"

# Default DNS Cluster IP
[string]$global:DNSClusterIP = ""

# Default Kubernetes Service CIDR
[string]$global:ServiceCIDR = ""

# Customer VPC CIDR Range
[string[]]$global:VPCCIDRRange = ""

# Service host to host kubelet and kube-proxy
[string]$ServiceHostExe = "$EKSBinDir\EKS-WindowsServiceHost.exe"

function Get-EC2MetaData {
<#
.SYNOPSIS
Gets data from EC2 meta data
.PARAMETER Path
Specifis the path to the meta data.
.OUTPUTS
Returns meta data.
#>
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory=$true)]
    [string]$Path
  )
  [string]$Prefix = 'http://169.254.169.254/'
  return Invoke-RestMethod -Uri ($Prefix + $Path)
}

function Update-KubeConfig {
<#
.SYNOPSIS
Creates/Updates kubeconfig file
#>
  # Update only if the APIServerEndPoint and Base64ClusterCA are empty.
  if ($APIServerEndpoint -and $Base64ClusterCA) {
    Write-Information "APIServer Endpoint and Cluster CA are being passed, bypassing Get-EKSCluster call."
  } else {
    Write-Information "Calling Get-EKSCluster to get cluster information."

    # Get-EKSCluster call.
    if (-not [string]::IsNullOrEmpty($Endpoint)) {
      $EKSCluster = Get-EKSCluster -Name $EKSClusterName -EndpointUrl $Endpoint
    } else {
      $EKSCluster = Get-EKSCluster -Name $EKSClusterName
    }

    $Base64ClusterCA = $EKSCluster.CertificateAuthority.Data
    $APIServerEndpoint = $EKSCluster.Endpoint
  }

  [System.Convert]::FromBase64String($Base64ClusterCA) | Set-Content -Encoding Byte $EKSClusterCACertFile

  [string]$ZONE = Get-EC2MetaData 'latest/meta-data/placement/availability-zone'
  [string]$AWS_REGION = $ZONE.Substring(0, $ZONE.length - 1)

  [string]$KubeConfig = @"
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: $EKSClusterCACertFile
    server: $APIServerEndpoint
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubelet
  name: kubelet
current-context: kubelet
users:
- name: kubelet
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: $IAMAuthenticator
      args:
        - `"token`"
        - `"-i`"
        - `"$EKSClusterName`"
        - --region
        - `"$AWS_REGION`"
"@

  Set-Content -Value $KubeConfig -Path $KubeConfigFile -Encoding ASCII
}

function Get-VPCCIDRRange {
<#
.SYNOPSIS
Returns VPC CIDR block array
#>
  [string]$EniMACAddress = Get-EC2MetaData 'latest/meta-data/mac'
  [string[]]$VPCCIDRblock = (Get-EC2MetaData "latest/meta-data/network/interfaces/macs/$EniMACAddress/vpc-ipv4-cidr-blocks").Split("`n")
  return $VPCCIDRblock;
}

function Initialize-DefaultValues {
<#
.SYNOPSIS
Initialize default values.
#>
  $global:DNSClusterIP = "10.100.0.10"
  $global:ServiceCIDR = "10.100.0.0/16"
  $global:VPCCIDRRange = Get-VPCCIDRRange
  $TenRange = $VPCCIDRRange | Where-Object {$_ -like '10.*'}

  if ($TenRange -ne $null) {
    $global:DNSClusterIP = '172.20.0.10'
    $global:ServiceCIDR = '172.20.0.0/16'
  }
}

function Update-Kubeletconfig {
<#
.SYNOPSIS
Creates & updates kubelet config file
#>
  [string]$ClientCAFile =  ConvertTo-Json $EKSClusterCACertFile

  [string]$KubeletConfig = @"
{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "address": "0.0.0.0",
  "authentication": {
    "anonymous": {
      "enabled": false
    },
    "webhook": {
      "cacheTTL": "2m0s",
      "enabled": true
    },
    "x509": {
      "clientCAFile": $ClientCAFile
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "clusterDomain": "cluster.local",
  "hairpinMode": "hairpin-veth",
  "cgroupDriver": "cgroupfs",
  "cgroupRoot": "/",
  "featureGates": {
    "RotateKubeletServerCertificate": true
  },
  "serializeImagePulls": false,
  "serverTLSBootstrap": true,
  "clusterDNS": [
    `"$DNSClusterIP`"
  ]
}
"@

  Set-Content -Value $KubeletConfig -Path $KubeletConfigFile -Encoding ASCII
}

function Update-EKSCNIConfig {
<#
.SYNOPSIS
Creates/Updates KES CNI plugin config file
#>
  [string]$CNIConfigFile = "$CNIConfigDir\vpc-shared-eni.conf"

  [string]$EniMACAddress = Get-EC2MetaData 'latest/meta-data/mac'
  [string]$EniIPAddress = Get-EC2MetaData 'latest/meta-data/local-ipv4'
  [string]$SubnetCIDR = Get-EC2MetaData "latest/meta-data/network/interfaces/macs/$EniMACAddress/subnet-ipv4-cidr-block"
  [string]$SubnetMaskBits = $SubnetCIDR.Split('/', 2)[1]
  [System.Collections.ArrayList]$GatewayIPAddress = (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop.Split("`n")

  [string[]]$DNSSuffixSearchList = ConvertTo-Json @("{%namespace%}.svc.cluster.local","svc.cluster.local","cluster.local")
  
  # If there's only one VPCCIDR Range, the following step will still convert this to array with single entry
  $ClusterCIDR = ConvertTo-Json @($VPCCIDRRange)

  [string]$CNIConfig = @"
{
  "cniVersion": "0.3.1",
  "name": "vpc",
  "type": "vpc-shared-eni",
  "eniMACAddress": "$EniMACAddress",
  "eniIPAddress": "$EniIPAddress/$SubnetMaskBits",
  "gatewayIPAddress": "$($GatewayIPAddress[0])",
  "vpcCIDRs": $ClusterCIDR,
  "serviceCIDR": "$ServiceCIDR",
  "dns": {
    "nameservers": ["$DNSClusterIP"],
    "search": $DNSSuffixSearchList
  }
}
"@

  Set-Content -Value $CNIConfig -Path $CNIConfigFile -Encoding ASCII
}

function Register-KubernetesServices {
  <#
  .SYNOPSIS
  Registers kubelet and kube-proxy services
  .PARAMETER KubeletServiceName
  Kubelet service name
  .PARAMETER KubeProxyServiceName
  Kube-proxy service name
  #>
    [CmdletBinding()]
    param(
      [Parameter(Mandatory=$true)]
      [string]$KubeletServiceName,
      [Parameter(Mandatory=$true)]
      [string]$KubeProxyServiceName
    )
  
    [string]$PodInfraContainerImage = Get-EKSPauseImage
    [string]$versionArgs = Get-VersionArguments
    [string]$InternalIP = Get-EC2MetaData 'latest/meta-data/local-ipv4'
    [string]$HostName = Get-EC2MetaData 'latest/meta-data/local-hostname'
  
    [string]$KubeletArgs = [string]::Join(' ', @(
       "--node-ip=$InternalIP"
    ))
  
    [string]$KubeletArgs = [string]::Join(' ', @(
      "--cloud-provider=aws",
      "--kubeconfig=`"$KubeConfigFile`"",
      "--hostname-override=$HostName",
      "--v=1",
      "--pod-infra-container-image=`"$PodInfraContainerImage`"",
      "--resolv-conf=`"`"",
      "--enable-debugging-handlers",
      "--image-pull-progress-deadline=20m",
      "--cgroups-per-qos=false",
      "--enforce-node-allocatable=`"`"",
      "--network-plugin=cni",
      "--cni-bin-dir=`"$CNIBinDir`"",
      "--cni-conf-dir=`"$CNIConfigDir`"",
      "--config=`"$KubeletConfigFile`"",
      "--logtostderr=true",
      $KubeletArgs,
      $KubeletExtraArgs,
      $versionArgs
    ))  

  New-Service -Name $KubeletServiceName -BinaryPathName "`"$ServiceHostExe`" $KubeletServiceName `"$Kubelet`" $KubeletArgs"

  # There's a bug when we used custom dns name. Upstream bug has been filed. https://github.com/kubernetes/kubernetes/issues/85616 
  # https://v1-14.docs.kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#troubleshooting (Check 6. vNICs and HNS endpoints of containers are being deleted)
  # To workaround this issue, we'll use Get-EC2Instance to get the privatedns name
  [string]$InstanceId = Get-EC2MetaData 'latest/meta-data/instance-id'
  [string]$InstancePrivateDnsName = $HostName
  $Instance = Get-EC2Instance -InstanceId $InstanceId

  if ($Instance.Instances.Count -gt 0) {
    $InstancePrivateDnsName = $Instance.Instances[0].PrivateDnsName
  }

  [string]$EniMACAddress = Get-EC2MetaData 'latest/meta-data/mac'
  [string]$ClusterCIDR = Get-EC2MetaData "latest/meta-data/network/interfaces/macs/$EniMACAddress/vpc-ipv4-cidr-block"
  
  $kubeproxyVersionCmd = "& `"$Kubeproxy`" --version"
  $kubeProxyVersionID = (Invoke-Expression -Command $kubeproxyVersionCmd).Split('.')[1]

  # For kube-proxy version 1.16* and higher, the flag --resource-container is deprecated and should not be used.
  [string]$KubeProxyArgs = [string]::Join(' ', @(
      "--kubeconfig=`"$KubeConfigFile`"",
      "--v=1",
      "--proxy-mode=kernelspace",
      "--hostname-override=`"$InstancePrivateDnsName`"",
      "--feature-gates=`"WinDSR=true`"",
      "--enable-dsr=true",
      "--cluster-cidr=`"$ClusterCIDR`"",
      "--logtostderr=true"
    ))

  if ($kubeProxyVersionID -lt 16) {
    $KubeProxyArgs = $KubeProxyArgs + "--resource-container=`"`""
  }
  
  New-Service -Name $KubeProxyServiceName -BinaryPathName "`"$ServiceHostExe`" $KubeProxyServiceName `"$Kubeproxy`" $KubeProxyArgs"
}

function Generate-ResolvConf {
<#
.SYNOPSIS
Generates resolv.conf file in c:/etc/resolv.conf to be consumed by CoreDns POD
#>
  [System.IO.DirectoryInfo]$ResolvDir = "c:\etc"
  [string]$ResolvFile = "${ResolvDir}\resolv.conf"

  # Creating resolv dir, if it doesn't exist
  if(-not $ResolvDir.Exists) {
    Write-Information "Creating resolv directory : $ResolvDir"
    $ResolvDir.Create()
  }

  # Getting unique comma separated Dns servers from the Ipv4 network interfaces (AddressFamily 2 represents IPv4)
  [string]$Dnsservers = (Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq "2" -and $_.ServerAddresses -ne ""} | Select  -Expandproperty ServerAddresses -unique) -join ","
  Write-Information "Unique Dns servers : $Dnsservers"

  [string]$ResolvContent = "nameserver $Dnsservers"
  Set-Content -Value $ResolvContent -Path $ResolvFile -Encoding ASCII
}

# Initialize AWS default configuration 
Write-Information 'Initializing AWS default configurations...'
Initialize-AWSDefaultConfiguration

# Initialize default values
Write-Information 'Initializing default values...'
Initialize-DefaultValues

# Generating kube configuration
Write-Information 'Creating/Updating kubeconfig...'
Update-KubeConfig

# Generating EKS cni plugin configuration
Write-Information 'Creating/Updating EKS CNI plugin config...'
Update-EKSCNIConfig

# Generating kubelet configuration file 
Write-Information 'Creating/Updating kubelet configuration file...'
Update-Kubeletconfig

# Registering kubelet and kube-proxy services
Write-Information 'Registering kublet and kube-proxy services...'
Register-KubernetesServices 'kubelet' 'kube-proxy'

# Generating resolv.conf file to be used by coredns plugin
Write-Information 'Generating resolvconf file...'
Generate-ResolvConf

# Enable and run EKS Windows Startup task
Enable-ScheduledTask -TaskName $StartupTaskName
Start-ScheduledTask -TaskName $StartupTaskName

# SIG # Begin signature block
# MIIePQYJKoZIhvcNAQcCoIIeLjCCHioCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA6VljIV3MGc/5E
# jtrjvAmjIIc92ESISpfgbDxweQFs7qCCDJwwggXYMIIEwKADAgECAhABVznfx2xi
# Vuf0Y3KCrPFgMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xKzApBgNV
# BAMTIkRpZ2lDZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAoU0hBMikwHhcNMTcwNjAx
# MDAwMDAwWhcNMjAwNjA0MTIwMDAwWjCCAR0xHTAbBgNVBA8MFFByaXZhdGUgT3Jn
# YW5pemF0aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQIT
# CERlbGF3YXJlMRAwDgYDVQQFEwc0MTUyOTU0MRgwFgYDVQQJEw80MTAgVGVycnkg
# QXZlIE4xDjAMBgNVBBETBTk4MTA5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEiMCAGA1UEChMZQW1hem9uIFdlYiBT
# ZXJ2aWNlcywgSW5jLjEUMBIGA1UECxMLRUMyIFdpbmRvd3MxIjAgBgNVBAMTGUFt
# YXpvbiBXZWIgU2VydmljZXMsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQDIcVfNSR3j5LoUqVUMtxS4NIJq/qOGQMGnTz95nmtpLOG8nv47GzUx
# zFkqnFmDxxjV9LUoMd5yZhVWyfEIMv7RsV0RhMZqJ/rutNfwt3r/4htqxDqiUHwN
# UKtqoHOw0Q2qSyKFbawCUbm/Bf3r/ya5ACbEz/abzCivvJsvQoRtflyfCemwF2Qu
# K8aw5c98Ab9xl0/ZJgd+966Bvxjf2VVKWf5pOuQKNo6ncZOU9gtgk8uV8h5yIttF
# sJP7KpN/hoXZC88EZXzjizSuLhutd7TEzBY56Lf9q0giZ+R8iiYQdenkKBGp75uv
# UqbJV+hjndohgKRZ8EnWQFVvVm2raAZTAgMBAAGjggHBMIIBvTAfBgNVHSMEGDAW
# gBSP6H7wbTJqAAUjx3CXajqQ/2vq1DAdBgNVHQ4EFgQUpJ202cGjSh7SNUwws5w6
# QmE9IYUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHsGA1Ud
# HwR0MHIwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9FVkNvZGVTaWdu
# aW5nU0hBMi1nMS5jcmwwN6A1oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9F
# VkNvZGVTaWduaW5nU0hBMi1nMS5jcmwwSwYDVR0gBEQwQjA3BglghkgBhv1sAwIw
# KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAHBgVn
# gQwBAzB+BggrBgEFBQcBAQRyMHAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBIBggrBgEFBQcwAoY8aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0RVZDb2RlU2lnbmluZ0NBLVNIQTIuY3J0MAwGA1UdEwEB/wQC
# MAAwDQYJKoZIhvcNAQELBQADggEBAATn4LxNeqlebC8j+gebBiwGYYbc8mM+5NUp
# me5SdJHXsOQptpl9jnZFboEVDltnxfHEMtebLGqX5kz7weqt5HpWatcjvMTTbZrq
# OMTVvsrNgcSjJ/VZoaWqmFsu4uHuwHXCHyqFUA5BxSqJrMjLLYNh5SE/Z8jQ2BAY
# nZhahetnz7Od2IoJzNgRqSHM/OXsZrTKsxv+o8qPqUKwhu+5HFHS+fXXvv5iZ9MO
# LcKTPZYecojbgdZCk+qCYuhyThSR3AUdlRAHHnJyMckNUitEiRNQtxXZ8Su1yBF5
# BExMdUEFAGCHyXq3zUg5g+6Ou53VYmGMJNTIDh77kp10b8usIB4wgga8MIIFpKAD
# AgECAhAD8bThXzqC8RSWeLPX2EdcMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xKzApBgNVBAMTIkRpZ2lDZXJ0IEhpZ2ggQXNzdXJhbmNlIEVWIFJvb3Qg
# Q0EwHhcNMTIwNDE4MTIwMDAwWhcNMjcwNDE4MTIwMDAwWjBsMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSswKQYDVQQDEyJEaWdpQ2VydCBFViBDb2RlIFNpZ25pbmcgQ0EgKFNIQTIp
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp1P6D7K1E/Fkz4SA/K6A
# NdG218ejLKwaLKzxhKw6NRI6kpG6V+TEyfMvqEg8t9Zu3JciulF5Ya9DLw23m7RJ
# Ma5EWD6koZanh08jfsNsZSSQVT6hyiN8xULpxHpiRZt93mN0y55jJfiEmpqtRU+u
# fR/IE8t1m8nh4Yr4CwyY9Mo+0EWqeh6lWJM2NL4rLisxWGa0MhCfnfBSoe/oPtN2
# 8kBa3PpqPRtLrXawjFzuNrqD6jCoTN7xCypYQYiuAImrA9EWgiAiduteVDgSYuHS
# cCTb7R9w0mQJgC3itp3OH/K7IfNs29izGXuKUJ/v7DYKXJq3StMIoDl5/d2/PToJ
# JQIDAQABo4IDWDCCA1QwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwfwYIKwYBBQUHAQEEczBxMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSQYIKwYBBQUHMAKGPWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJv
# b3RDQS5jcnQwgY8GA1UdHwSBhzCBhDBAoD6gPIY6aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDBAoD6gPIY6
# aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVW
# Um9vdENBLmNybDCCAcQGA1UdIASCAbswggG3MIIBswYJYIZIAYb9bAMCMIIBpDA6
# BggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBv
# c2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAg
# AG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBz
# AHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABo
# AGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABo
# AGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBu
# AHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAg
# AGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQBy
# AGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjAdBgNVHQ4EFgQUj+h+
# 8G0yagAFI8dwl2o6kP9r6tQwHwYDVR0jBBgwFoAUsT7DaQP4v0cB1JgmGggC72Nk
# K8MwDQYJKoZIhvcNAQELBQADggEBABkzSgyBMzfbrTbJ5Mk6u7UbLnqi4vRDQhee
# v06hTeGx2+mB3Z8B8uSI1en+Cf0hwexdgNLw1sFDwv53K9v515EzzmzVshk75i7W
# yZNPiECOzeH1fvEPxllWcujrakG9HNVG1XxJymY4FcG/4JFwd4fcyY0xyQwpojPt
# jeKHzYmNPxv/1eAal4t82m37qMayOmZrewGzzdimNOwSAauVWKXEU1eoYObnAhKg
# uSNkok27fIElZCG+z+5CGEOXu6U3Bq9N/yalTWFL7EZBuGXOuHmeCJYLgYyKO4/H
# mYyjKm6YbV5hxpa3irlhLZO46w4EQ9f1/qbwYtSZaqXBwfBklIAxghD3MIIQ8wIB
# ATCBgDBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBFViBDb2Rl
# IFNpZ25pbmcgQ0EgKFNIQTIpAhABVznfx2xiVuf0Y3KCrPFgMA0GCWCGSAFlAwQC
# AQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
# IMYLlUqnJiEJG2SBjwpur+Zvvkde6ErVMbszzQ/HVCfYMA0GCSqGSIb3DQEBAQUA
# BIIBAGS54h2O0AT7Hlbf7HKgu74rOHc2jmZx6whZKBxlXM2X0rM7vWnu/JQLAgqe
# 0W1bFaGVCLeQNm77GnyKh/uZ7EBB0kp3owPK4N2JkOQAKOIrPYAN91bOEqpsuU7l
# 1qbjqYU8emWi8kqKNATa8ZByyW0CxdaQqUNEwsc3Bpb9tQKzhenaUdogmrQWfVr/
# ODa1CcSCeLeSXFOTd/c4jnHPKQDpX8/FPGJ229OnZolkT0Xliec4SG0lHpDNXcBa
# cOJPsTQR3OYwdjDIJCDdOqisb+T7q1/WEGSAi3vs20oQWc8TfbJCht39qqWyGOWj
# h9qrX2HaEEql7h+1J51Bld2oSXihgg7JMIIOxQYKKwYBBAGCNwMDATGCDrUwgg6x
# BgkqhkiG9w0BBwKggg6iMIIOngIBAzEPMA0GCWCGSAFlAwQCAQUAMHgGCyqGSIb3
# DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEFAAQgdtrK
# xC/172wL+1+oP5njtQD5HhgSR3Wne9kDAfveppsCEQDoBoWO87hphzTXinz0l6+b
# GA8yMDIwMDQzMDA3MjUxNFqgggu7MIIGgjCCBWqgAwIBAgIQBM0/hWiudsYbsP5x
# YMynbTANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhE
# aWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTE5MTAw
# MTAwMDAwMFoXDTMwMTAxNzAwMDAwMFowTDELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMSQwIgYDVQQDExtUSU1FU1RBTVAtU0hBMjU2LTIwMTkt
# MTAtMTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpZDWc+qmYZWQb
# 5BfcuCk2zGcJWIVNMODJ/+U7PBEoUK8HMeJdCRjC9omMaQgEI+B3LZ0V5bjooWqO
# /9Su0noW7/hBtR05dcHPL6esRX6UbawDAZk8Yj5+ev1FlzG0+rfZQj6nVZvfWk9Y
# AqgyaSITvouCLcaYq2ubtMnyZREMdA2y8AiWdMToskiioRSl+PrhiXBEO43v+6T0
# w7m9FCzrDCgnJYCrEEsWEmALaSKMTs3G1bJlWSHgfCwSjXAOj4rK4NPXszl3UNBC
# LC56zpxnejh3VED/T5UEINTryM6HFAj+HYDd0OcreOq/H3DG7kIWUzZFm1MZSWKd
# egKblRSjAgMBAAGjggM4MIIDNDAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCCAb8GA1UdIASCAbYwggGyMIIBoQYJ
# YIZIAYb9bAcBMIIBkjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8A
# ZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQA
# aQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUA
# IABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUA
# IABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQA
# IAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEA
# bgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUA
# aQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwHwYD
# VR0jBBgwFoAU9LbhIB3+Ka7S5GGlsqIlssgXNW4wHQYDVR0OBBYEFFZTD8HGB6dN
# 19huV3KAUEzk7J7BMHEGA1UdHwRqMGgwMqAwoC6GLGh0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMDKgMKAuhixodHRwOi8vY3JsNC5k
# aWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDCBhQYIKwYBBQUHAQEEeTB3
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTwYIKwYBBQUH
# MAKGQ2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1
# cmVkSURUaW1lc3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggEBAC6DoUQF
# SgTjuTJS+tmB8Bq7+AmNI7k92JKh5kYcSi9uejxjbjcXoxq/WCOyQ5yUg045CbAs
# 6Mfh4szty3lrzt4jAUftlVSB4IB7ErGvAoapOnNq/vifwY3RIYzkKYLDigtgAAKd
# H0fEn7QKaFN/WhCm+CLm+FOSMV/YgoMtbRNCroPBEE6kJPRHnN4PInJ3XH9P6TmY
# K1eSRNfvbpPZQ8cEM2NRN1aeRwQRw6NYVCHY4o5W10k/V/wKnyNee/SUjd2dGrvf
# eiqm0kWmVQyP9kyK8pbPiUbcMbKRkKNfMzBgVfX8azCsoe3kR04znmdqKLVNwu1b
# l4L4y6kIbFMJtPcwggUxMIIEGaADAgECAhAKoSXW1jIbfkHkBdo2l8IVMA0GCSqG
# SIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFz
# c3VyZWQgSUQgUm9vdCBDQTAeFw0xNjAxMDcxMjAwMDBaFw0zMTAxMDcxMjAwMDBa
# MHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJl
# ZCBJRCBUaW1lc3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQC90DLuS82Pf92puoKZxTlUKFe2I0rEDgdFM1EQfdD5fU1ofue2oPSNs4jk
# l79jIZCYvxO8V9PD4X4I1moUADj3Lh477sym9jJZ/l9lP+Cb6+NGRwYaVX4LJ37A
# ovWg4N4iPw7/fpX786O6Ij4YrBHk8JkDbTuFfAnT7l3ImgtU46gJcWvgzyIQD3XP
# cXJOCq3fQDpct1HhoXkUxk0kIzBdvOw8YGqsLwfM/fDqR9mIUF79Zm5WYScpiYRR
# 5oLnRlD9lCosp+R1PrqYD4R/nzEU1q3V8mTLex4F0IQZchfxFwbvPc3WTe8GQv2i
# UypPhR3EHTyvz9qsEPXdrKzpVv+TAgMBAAGjggHOMIIByjAdBgNVHQ4EFgQU9Lbh
# IB3+Ka7S5GGlsqIlssgXNW4wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNt
# yA8wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAww
# CgYIKwYBBQUHAwgweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6
# MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwUAYDVR0gBEkwRzA4BgpghkgBhv1s
# AAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IBAQBxlRLpUYdWac3v3dp8qmN6
# s3jPBjdAhO9LhL/KzwMC/cWnww4gQiyvd/MrHwwhWiq3BTQdaq6Z+CeiZr8JqmDf
# dqQ6kw/4stHYfBli6F6CJR7Euhx7LCHi1lssFDVDBGiy23UC4HLHmNY8ZOUfSBAY
# X4k4YU1iRiSHY4yRUiyvKYnleB/WCxSlgNcSR3CzddWThZN+tpJn+1Nhiaj1a5bA
# 9FhpDXzIAbG5KHW3mWOFIoxhynmUfln8jA/jb7UBJrZspe6HUSHkWGCbugwtK22i
# xH67xCUrRwIIfEmuE7bhfEJCKMYYVs9BNLZmXbZ0e/VWMyIvIjayS6JKldj1po5S
# MYICTTCCAkkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNl
# cnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQBM0/hWiudsYbsP5x
# YMynbTANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwHAYJKoZIhvcNAQkFMQ8XDTIwMDQzMDA3MjUxNFowKwYLKoZIhvcNAQkQAgwx
# HDAaMBgwFgQUAyW9UF7aljAtwi9PoB5MKL4oNMUwLwYJKoZIhvcNAQkEMSIEIM+/
# 1q6nYSeye+GK+Sv69a+hJl9JMFL07fwf8saevIlTMA0GCSqGSIb3DQEBAQUABIIB
# AByx9jNjBbU16jWe4/V4I+YjtvtoVDdItZbzuCysvfycAkBERtZ4PrbbIPVZyQpj
# aItuT7bxsMFfaxO7Zs771TJW1yKCyclwP6h5h5/SaaqU9KSHPjZHtLjGM1MXifWh
# 9MuwjrrX8alRlEzPQ00fSdGxniKs4qXOMRpFxW/04v8a4EG/tlM9Cn7CpVru/twj
# eXEtYljby3esgf2cFMU5hHVmhwhjust4L21qQuVWDa+7Jj6mqRJWQLqftQj6WAod
# wQqZGQ3GrwG9dOWkzQwtit7xdGQETkS/g/eOAqqdmoCVzxHnpvhwo3p+j/CI0k4b
# uZIjkqU4yhIBe/8wVJ0+ebc=
# SIG # End signature block
