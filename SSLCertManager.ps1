<#
.SYNOPSIS
    A PowerShell script for managing and renewing SSL certificates using a Windows CA.

.DESCRIPTION
    This script provides functions to interact with a Windows Certificate Authority (CA) for certificate management.
    It supports renewing certificates for various server types, checking issued certificates, and more.
    Supported server types: Manual, WindowsMachine, iDRAC, vCenter.

.PARAMETER CAConfig
    The CA configuration string in the format "CAHost\CAName".

.PARAMETER CATemplate
    The certificate template name (e.g., "WebServer").

.PARAMETER Hostname
    The hostname (FQDN) for which to renew the certificate.

.PARAMETER ServerType
    The type of server: Manual, WindowsMachine, iDRAC, vCenter.

.PARAMETER Credential
    PSCredential object for authenticating to the target server.

.PARAMETER CSRFile
    For Manual type: Path to the CSR file to submit.

.PARAMETER CertFile
    For Manual type: Path to save the signed certificate.

.PARAMETER Organization
    Organization name for CSR.

.PARAMETER OrganizationalUnit
    OU name for CSR.

.PARAMETER Locality
    Locality (city) for CSR.

.PARAMETER State
    State or province for CSR.

.PARAMETER Country
    Country code (e.g., US) for CSR.

.PARAMETER KeyLength
    Key length (e.g., 2048).

.EXAMPLE
    # Renew for Windows Machine
    Renew-Certificate -CAConfig "cahost\caname" -CATemplate "WebServer" -Hostname "server.example.com" -ServerType "WindowsMachine" -Credential (Get-Credential) -Organization "Example Corp" -Country "US"

.EXAMPLE
    # Get expiring certificates from CA
    Get-ExpiringCertificates -CAConfig "cahost\caname" -Days 90

.EXAMPLE
    # Check certificates for a hostname
    Get-HostCertificates -CAConfig "cahost\caname" -Hostname "server.example.com"

.NOTES
    Requires certutil.exe and certreq.exe available in PATH.
    For iDRAC: Requires racadm.exe in PATH.
    For vCenter: Requires VMware.PowerCLI module installed.
    Run with administrative privileges.
    Assumes current user has permissions to the CA; no separate CA credential supported.
#>

function Get-CATemplates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig
    )

    $output = certutil -config $CAConfig -template
    $templates = @()
    $output | ForEach-Object {
        if ($_ -match "^Template\[(\d+)\]:\s*(.+)$") {
            $templates += $matches[2].Trim()
        }
    }
    return $templates
}

function Get-IssuedCertificates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig,
        [string]$Restrict = "Disposition=20"
    )

    $columns = "RequestID,RequesterName,NotBefore,NotAfter,SerialNumber,CertificateTemplate,CommonName,Disposition"
    $output = certutil -config $CAConfig -view csv -restrict $Restrict -out $columns
    return $output | ConvertFrom-Csv
}

function Get-HostCertificates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig,
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )

    $certs = Get-IssuedCertificates -CAConfig $CAConfig
    $hostCerts = $certs | Where-Object { $_.CommonName -like "*$Hostname*" }
    if ($hostCerts) {
        $hostCerts | Select-Object CommonName, NotBefore, NotAfter, SerialNumber, CertificateTemplate | Format-Table
    } else {
        Write-Output "No certificates found for hostname $Hostname."
    }
}

function Get-ExpiringCertificates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig,
        [int]$Days = 90
    )

    $restrict = "NotAfter<=now+$Days`days,NotAfter>now,Disposition=20"
    $certs = Get-IssuedCertificates -CAConfig $CAConfig -Restrict $restrict
    if ($certs) {
        $certs | Select-Object CommonName, NotBefore, NotAfter, SerialNumber, CertificateTemplate | Format-Table
    } else {
        Write-Output "No certificates expiring within $Days days."
    }
}

function Get-SupportedServerTypes {
    [CmdletBinding()]
    return @("Manual", "WindowsMachine", "iDRAC", "vCenter")
}

function Renew-Certificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig,
        [Parameter(Mandatory=$true)]
        [string]$CATemplate,
        [Parameter(Mandatory=$true)]
        [string]$Hostname,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Manual", "WindowsMachine", "iDRAC", "vCenter")]
        [string]$ServerType,
        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,
        [string]$CSRFile,  # For Manual
        [string]$CertFile, # For Manual
        [string]$Organization = "Example Org",
        [string]$OrganizationalUnit = "IT",
        [string]$Locality = "City",
        [string]$State = "State",
        [string]$Country = "US",
        [int]$KeyLength = 2048
    )

    switch ($ServerType) {
        "Manual" {
            if (-not $CSRFile -or -not $CertFile) {
                throw "CSRFile and CertFile required for Manual type."
            }
            $reqOut = certreq -submit -config $CAConfig -attrib "CertificateTemplate:$CATemplate" $CSRFile
            if ($reqOut -match "RequestId: (\d+)") {
                $reqId = $matches[1]
            } else {
                throw "Failed to submit CSR: $reqOut"
            }
            certreq -retrieve -config $CAConfig $reqId $CertFile
            Write-Output "Signed certificate saved to $CertFile"
        }
        "WindowsMachine" {
            $infContent = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject="CN=$Hostname"
KeySpec=1
KeyLength=$KeyLength
Exportable=TRUE
MachineKeySet=TRUE
SMIME=FALSE
PrivateKeyArchive=FALSE
UserProtected=FALSE
UseExistingKeySet=FALSE
ProviderName="Microsoft RSA SChannel Cryptographic Provider"
ProviderType=12
RequestType=PKCS10
KeyUsage=0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1

[RequestAttributes]
CertificateTemplate=$CATemplate
"@
            $infFile = [System.IO.Path]::GetTempFileName()
            $infContent | Out-File -FilePath $infFile -Encoding ASCII

            $csrFile = [System.IO.Path]::GetTempFileName()

            Invoke-Command -ComputerName $Hostname -Credential $Credential -ScriptBlock {
                param($inf, $csr)
                certreq -new $inf $csr
            } -ArgumentList $infFile, $csrFile

            $reqOut = certreq -submit -config $CAConfig $csrFile
            if ($reqOut -match "RequestId: (\d+)") {
                $reqId = $matches[1]
            } else {
                throw "Failed to submit CSR: $reqOut"
            }
            $cerFile = [System.IO.Path]::GetTempFileName()
            certreq -retrieve -config $CAConfig $reqId $cerFile

            Invoke-Command -ComputerName $Hostname -Credential $Credential -ScriptBlock {
                param($cer)
                certreq -accept $cer
            } -ArgumentList $cerFile

            Remove-Item $infFile, $csrFile, $cerFile
            Write-Output "Certificate renewed and installed on $Hostname"
        }
        "iDRAC" {
            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrCommonName $Hostname
            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrOrganizationName $Organization
            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrOrganizationUnit $OrganizationalUnit
            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrLocalityName $Locality
            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrStateName $State
            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrCountryCode $Country

            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) sslcsrgen -g

            Start-Sleep -Seconds 10

            $csrFile = [System.IO.Path]::GetTempFileName()
            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) sslcertdownload -t 2 -f $csrFile

            $reqOut = certreq -submit -config $CAConfig -attrib "CertificateTemplate:$CATemplate" $csrFile
            if ($reqOut -match "RequestId: (\d+)") {
                $reqId = $matches[1]
            } else {
                throw "Failed to submit CSR: $reqOut"
            }
            $cerFile = [System.IO.Path]::GetTempFileName()
            certreq -retrieve -config $CAConfig $reqId $cerFile

            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) sslcertupload -t 1 -f $cerFile

            racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) racreset

            Remove-Item $csrFile, $cerFile
            Write-Output "Certificate renewed on iDRAC $Hostname"
        }
        "vCenter" {
            Import-Module VMware.PowerCLI -ErrorAction Stop

            Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
            Connect-VIServer -Server $Hostname -Credential $Credential

            $csr = New-VICertificateCsr -KeySize $KeyLength -CommonName $Hostname -Organization $Organization -OrganizationalUnit $OrganizationalUnit -Locality $Locality -StateOrProvince $State -Country $Country
            $csrFile = [System.IO.Path]::GetTempFileName()
            $csr.Csr | Out-File $csrFile -Encoding ASCII

            $reqOut = certreq -submit -config $CAConfig -attrib "CertificateTemplate:$CATemplate" $csrFile
            if ($reqOut -match "RequestId: (\d+)") {
                $reqId = $matches[1]
            } else {
                throw "Failed to submit CSR: $reqOut"
            }
            $cerFile = [System.IO.Path]::GetTempFileName()
            certreq -retrieve -config $CAConfig $reqId $cerFile

            Set-VICertificate -Certificate (Get-Content $cerFile -Raw)

            Disconnect-VIServer -Confirm:$false

            Remove-Item $csrFile, $cerFile
            Write-Output "Certificate renewed on vCenter $Hostname. vCenter will reboot."
        }
    }
}