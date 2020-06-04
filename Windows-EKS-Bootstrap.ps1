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
  [string]$KubeProxyArgs = [string]::Join(' ', @(
    "--kubeconfig=`"$KubeConfigFile`"",
    "--v=1",
    "--proxy-mode=kernelspace",
    "--hostname-override=$InstancePrivateDnsName",
    "--feature-gates=`"WinDSR=true`"",
    "--enable-dsr=true",
    "--cluster-cidr=`"$ClusterCIDR`"",
    "--resource-container=`"`"",
    "--logtostderr=true"
  ))

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