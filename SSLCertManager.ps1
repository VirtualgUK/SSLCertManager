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
    Logs are written to a file in the script's directory with timestamp (e.g., SSLCertManager_20250729.log).
#>

# Global variable for log file path
$script:LogFile = $null

function Start-Logging {
    [CmdletBinding()]
    param ()
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:LogFile = Join-Path $scriptDir "SSLCertManager_$timestamp.log"
    Write-Output "Logging started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') to $script:LogFile" | Out-File -FilePath $script:LogFile -Encoding UTF8
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO", "ERROR", "WARNING")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Output $logMessage | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    Write-Verbose $logMessage
}

function Get-CATemplates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig
    )

    Start-Logging
    Write-Log "Retrieving certificate templates from CA: $CAConfig"
    try {
        $output = certutil -config $CAConfig -template
        $templates = @()
        $output | ForEach-Object {
            if ($_ -match "^Template\[(\d+)\]:\s*(.+)$") {
                $templates += $matches[2].Trim()
            }
        }
        Write-Log "Successfully retrieved $($templates.Count) templates"
        return $templates
    } catch {
        Write-Log "Failed to retrieve templates: $_" -Level "ERROR"
        throw
    }
}

function Get-IssuedCertificates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig,
        [string]$Restrict = "Disposition=20"
    )

    Start-Logging
    Write-Log "Retrieving issued certificates from CA: $CAConfig with restriction: $Restrict"
    try {
        $columns = "RequestID,RequesterName,NotBefore,NotAfter,SerialNumber,CertificateTemplate,CommonName,Disposition"
        $output = certutil -config $CAConfig -view csv -restrict $Restrict -out $columns
        $certs = $output | ConvertFrom-Csv
        Write-Log "Retrieved $($certs.Count) certificates"
        return $certs
    } catch {
        Write-Log "Failed to retrieve issued certificates: $_" -Level "ERROR"
        throw
    }
}

function Get-HostCertificates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig,
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )

    Start-Logging
    Write-Log "Checking certificates for hostname: $Hostname on CA: $CAConfig"
    try {
        $certs = Get-IssuedCertificates -CAConfig $CAConfig
        $hostCerts = $certs | Where-Object { $_.CommonName -like "*$Hostname*" }
        if ($hostCerts) {
            Write-Log "Found $($hostCerts.Count) certificates for $Hostname"
            $hostCerts | Select-Object CommonName, NotBefore, NotAfter, SerialNumber, CertificateTemplate | Format-Table
        } else {
            Write-Log "No certificates found for hostname $Hostname"
            Write-Output "No certificates found for hostname $Hostname."
        }
    } catch {
        Write-Log "Failed to check certificates for $Hostname: $_" -Level "ERROR"
        throw
    }
}

function Get-ExpiringCertificates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CAConfig,
        [int]$Days = 90
    )

    Start-Logging
    Write-Log "Checking for certificates expiring within $Days days on CA: $CAConfig"
    try {
        $restrict = "NotAfter<=now+$Days`days,NotAfter>now,Disposition=20"
        $certs = Get-IssuedCertificates -CAConfig $CAConfig -Restrict $restrict
        if ($certs) {
            Write-Log "Found $($certs.Count) certificates expiring within $Days days"
            $certs | Select-Object CommonName, NotBefore, NotAfter, SerialNumber, CertificateTemplate | Format-Table
        } else {
            Write-Log "No certificates expiring within $Days days"
            Write-Output "No certificates expiring within $Days days."
        }
    } catch {
        Write-Log "Failed to check expiring certificates: $_" -Level "ERROR"
        throw
    }
}

function Get-SupportedServerTypes {
    [CmdletBinding()]
    Start-Logging
    Write-Log "Retrieving supported server types"
    $types = @("Manual", "WindowsMachine", "iDRAC", "vCenter")
    Write-Log "Supported server types: $($types -join ', ')"
    return $types
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

    Start-Logging
    Write-Log "Starting certificate renewal for $Hostname (Type: $ServerType, Template: $CATemplate, CA: $CAConfig)"

    switch ($ServerType) {
        "Manual" {
            if (-not $CSRFile -or -not $CertFile) {
                Write-Log "CSRFile and CertFile required for Manual type" -Level "ERROR"
                throw "CSRFile and CertFile required for Manual type."
            }
            Write-Log "Submitting CSR from $CSRFile to CA"
            try {
                $reqOut = certreq -submit -config $CAConfig -attrib "CertificateTemplate:$CATemplate" $CSRFile
                if ($reqOut -match "RequestId: (\d+)") {
                    $reqId = $matches[1]
                    Write-Log "CSR submitted successfully, Request ID: $reqId"
                } else {
                    Write-Log "Failed to submit CSR: $reqOut" -Level "ERROR"
                    throw "Failed to submit CSR: $reqOut"
                }
                Write-Log "Retrieving signed certificate for Request ID: $reqId"
                certreq -retrieve -config $CAConfig $reqId $CertFile
                Write-Log "Signed certificate saved to $CertFile"
                Write-Output "Signed certificate saved to $CertFile"
            } catch {
                Write-Log "Manual certificate renewal failed: $_" -Level "ERROR"
                throw
            }
        }
        "WindowsMachine" {
            Write-Log "Generating INF file for WindowsMachine certificate"
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
            Write-Log "INF file created at $infFile"

            $csrFile = [System.IO.Path]::GetTempFileName()
            Write-Log "Generating CSR on $Hostname"

            try {
                Invoke-Command -ComputerName $Hostname -Credential $Credential -ScriptBlock {
                    param($inf, $csr)
                    certreq -new $inf $csr
                } -ArgumentList $infFile, $csrFile
                Write-Log "CSR generated successfully at $csrFile"
            } catch {
                Write-Log "Failed to generate CSR on $Hostname: $_" -Level "ERROR"
                throw
            }

            Write-Log "Submitting CSR to CA"
            try {
                $reqOut = certreq -submit -config $CAConfig $csrFile
                if ($reqOut -match "RequestId: (\d+)") {
                    $reqId = $matches[1]
                    Write-Log "CSR submitted successfully, Request ID: $reqId"
                } else {
                    Write-Log "Failed to submit CSR: $reqOut" -Level "ERROR"
                    throw "Failed to submit CSR: $reqOut"
                }
                $cerFile = [System.IO.Path]::GetTempFileName()
                Write-Log "Retrieving signed certificate for Request ID: $reqId"
                certreq -retrieve -config $CAConfig $reqId $cerFile
                Write-Log "Signed certificate retrieved to $cerFile"
            } catch {
                Write-Log "Failed to submit or retrieve certificate: $_" -Level "ERROR"
                throw
            }

            Write-Log "Installing certificate on $Hostname"
            try {
                Invoke-Command -ComputerName $Hostname -Credential $Credential -ScriptBlock {
                    param($cer)
                    certreq -accept $cer
                } -ArgumentList $cerFile
                Write-Log "Certificate installed successfully on $Hostname"
            } catch {
                Write-Log "Failed to install certificate on $Hostname: $_" -Level "ERROR"
                throw
            }

            Write-Log "Cleaning up temporary files"
            Remove-Item $infFile, $csrFile, $cerFile -ErrorAction SilentlyContinue
            Write-Log "Certificate renewal completed for $Hostname"
            Write-Output "Certificate renewed and installed on $Hostname"
        }
        "iDRAC" {
            Write-Log "Configuring iDRAC CSR for $Hostname"
            try {
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrCommonName $Hostname
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrOrganizationName $Organization
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrOrganizationUnit $OrganizationalUnit
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrLocalityName $Locality
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrStateName $State
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) set iDRAC.Security.CsrCountryCode $Country
                Write-Log "iDRAC CSR parameters set"
            } catch {
                Write-Log "Failed to set iDRAC CSR parameters: $_" -Level "ERROR"
                throw
            }

            Write-Log "Generating CSR on iDRAC"
            try {
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) sslcsrgen -g
                Write-Log "CSR generation initiated on iDRAC"
            } catch {
                Write-Log "Failed to generate CSR on iDRAC: $_" -Level "ERROR"
                throw
            }

            Start-Sleep -Seconds 10
            Write-Log "Waiting 10 seconds for CSR generation"

            $csrFile = [System.IO.Path]::GetTempFileName()
            Write-Log "Downloading CSR to $csrFile"
            try {
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) sslcertdownload -t 2 -f $csrFile
                Write-Log "CSR downloaded successfully"
            } catch {
                Write-Log "Failed to download CSR: $_" -Level "ERROR"
                throw
            }

            Write-Log "Submitting CSR to CA"
            try {
                $reqOut = certreq -submit -config $CAConfig -attrib "CertificateTemplate:$CATemplate" $csrFile
                if ($reqOut -match "RequestId: (\d+)") {
                    $reqId = $matches[1]
                    Write-Log "CSR submitted successfully, Request ID: $reqId"
                } else {
                    Write-Log "Failed to submit CSR: $reqOut" -Level "ERROR"
                    throw "Failed to submit CSR: $reqOut"
                }
                $cerFile = [System.IO.Path]::GetTempFileName()
                Write-Log "Retrieving signed certificate for Request ID: $reqId"
                certreq -retrieve -config $CAConfig $reqId $cerFile
                Write-Log "Signed certificate retrieved to $cerFile"
            } catch {
                Write-Log "Failed to submit or retrieve certificate: $_" -Level "ERROR"
                throw
            }

            Write-Log "Uploading certificate to iDRAC"
            try {
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) sslcertupload -t 1 -f $cerFile
                Write-Log "Certificate uploaded successfully"
            } catch {
                Write-Log "Failed to upload certificate: $_" -Level "ERROR"
                throw
            }

            Write-Log "Resetting iDRAC to apply certificate"
            try {
                racadm -r $Hostname -u $($Credential.UserName) -p $($Credential.GetNetworkCredential().Password) racreset
                Write-Log "iDRAC reset initiated"
            } catch {
                Write-Log "Failed to reset iDRAC: $_" -Level "ERROR"
                throw
            }

            Write-Log "Cleaning up temporary files"
            Remove-Item $csrFile, $cerFile -ErrorAction SilentlyContinue
            Write-Log "Certificate renewal completed for iDRAC $Hostname"
            Write-Output "Certificate renewed on iDRAC $Hostname"
        }
        "vCenter" {
            Write-Log "Connecting to vCenter $Hostname"
            try {
                Import-Module VMware.PowerCLI -ErrorAction Stop
                Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
                Connect-VIServer -Server $Hostname -Credential $Credential
                Write-Log "Connected to vCenter successfully"
            } catch {
                Write-Log "Failed to connect to vCenter: $_" -Level "ERROR"
                throw
            }

            Write-Log "Generating CSR for vCenter"
            try {
                $csr = New-VICertificateCsr -KeySize $KeyLength -CommonName $Hostname -Organization $Organization -OrganizationalUnit $OrganizationalUnit -Locality $Locality -StateOrProvince $State -Country $Country
                $csrFile = [System.IO.Path]::GetTempFileName()
                $csr.Csr | Out-File $csrFile -Encoding ASCII
                Write-Log "CSR generated and saved to $csrFile"
            } catch {
                Write-Log "Failed to generate CSR for vCenter: $_" -Level "ERROR"
                throw
            }

            Write-Log "Submitting CSR to CA"
            try {
                $reqOut = certreq -submit -config $CAConfig -attrib "CertificateTemplate:$CATemplate" $csrFile
                if ($reqOut -match "RequestId: (\d+)") {
                    $reqId = $matches[1]
                    Write-Log "CSR submitted successfully, Request ID: $reqId"
                } else {
                    Write-Log "Failed to submit CSR: $reqOut" -Level "ERROR"
                    throw "Failed to submit CSR: $reqOut"
                }
                $cerFile = [System.IO.Path]::GetTempFileName()
                Write-Log "Retrieving signed certificate for Request ID: $reqId"
                certreq -retrieve -config $CAConfig $reqId $cerFile
                Write-Log "Signed certificate retrieved to $cerFile"
            } catch {
                Write-Log "Failed to submit or retrieve certificate: $_" -Level "ERROR"
                throw
            }

            Write-Log "Installing certificate on vCenter"
            try {
                Set-VICertificate -Certificate (Get-Content $cerFile -Raw)
                Write-Log "Certificate installed successfully on vCenter"
            } catch {
                Write-Log "Failed to install certificate on vCenter: $_" -Level "ERROR"
                throw
            }

            Write-Log "Disconnecting from vCenter"
            Disconnect-VIServer -Confirm:$false
            Write-Log "Cleaning up temporary files"
            Remove-Item $csrFile, $cerFile -ErrorAction SilentlyContinue
            Write-Log "Certificate renewal completed for vCenter $Hostname"
            Write-Output "Certificate renewed on vCenter $Hostname. vCenter will reboot."
        }
    }
}