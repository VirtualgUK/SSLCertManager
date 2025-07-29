# SSL Certificate Renewal Script

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Overview

This PowerShell script automates the process of renewing SSL certificates using a Windows Certificate Authority (CA). It is highly parameterized for use across multiple environments and supports various server types, including Windows machines, iDRAC, and VMware vCenter. The script also provides functionality to check certificate templates, view issued certificates, and identify certificates nearing expiration, with detailed logging for tracking actions and errors.

## Features

- **Certificate Renewal**: Generates Certificate Signing Requests (CSRs), submits them to a Windows CA, and installs signed certificates.
- **Supported Server Types**:
  - `Manual`: Submit a CSR and retrieve a signed certificate as a file.
  - `WindowsMachine`: Installs certificates in the Windows machine's personal store.
  - `iDRAC`: Manages certificates for Dell iDRAC.
  - `vCenter`: Manages certificates for VMware vCenter.
- **Certificate Management**:
  - Retrieve available certificate templates from the CA.
  - Check existing certificates for a specific hostname, including expiry dates and issuing CA.
  - List certificates expiring within a specified period (default: 90 days).
- **Parameterized**: Configurable parameters for CA configuration, template, hostname, credentials, and CSR details (e.g., organization, country, key length).
- **Logging**: Writes detailed logs to a timestamped file in the script's directory (e.g., `SSLCertManager_20250729.log`).

## Prerequisites

- **PowerShell**: Version 5.1 or later.
- **Tools**:
  - `certutil.exe` and `certreq.exe` (included with Windows).
  - `racadm.exe` for iDRAC (must be in PATH).
  - `VMware.PowerCLI` module for vCenter (must be installed).
- **Permissions**: Administrative privileges on the machine running the script and appropriate permissions to access the CA.
- **Network**: Access to the CA and target servers.

## Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/VirtualgUK/SSLCertManager.git
   ```
2. Ensure prerequisites are met (see above).
3. Place the script (`RenewSslCertificates.ps1`) in a directory accessible to PowerShell.

## Usage

### Examples

1. **Renew a certificate for a Windows machine**:
   ```powershell
   $cred = Get-Credential
   .\RenewSslCertificates.ps1 -CAConfig "cahost\caname" -CATemplate "WebServer" -Hostname "server.example.com" -ServerType "WindowsMachine" -Credential $cred -Organization "Example Corp" -Country "US" -KeyLength 4096
   ```
   This renews a certificate for a Windows server, installs it in the machine's personal store, and logs all actions.

2. **Submit a manual CSR and retrieve the signed certificate**:
   ```powershell
   $cred = Get-Credential
   .\RenewSslCertificates.ps1 -CAConfig "cahost\caname" -CATemplate "WebServer" -Hostname "server.example.com" -ServerType "Manual" -Credential $cred -CSRFile "C:\Certs\server.csr" -CertFile "C:\Certs\server.cer"
   ```
   This submits an existing CSR to the CA and saves the signed certificate to a file.

3. **Renew a certificate for an iDRAC**:
   ```powershell
   $cred = Get-Credential
   .\RenewSslCertificates.ps1 -CAConfig "cahost\caname" -CATemplate "WebServer" -Hostname "idrac.example.com" -ServerType "iDRAC" -Credential $cred -Organization "Example Corp" -OrganizationalUnit "IT" -Locality "London" -State "England" -Country "GB"
   ```
   This generates a CSR on the iDRAC, submits it to the CA, uploads the signed certificate, and resets the iDRAC.

4. **Renew a certificate for a VMware vCenter**:
   ```powershell
   $cred = Get-Credential
   .\RenewSslCertificates.ps1 -CAConfig "cahost\caname" -CATemplate "WebServer" -Hostname "vcenter.example.com" -ServerType "vCenter" -Credential $cred -Organization "Example Corp" -Country "US"
   ```
   This renews the vCenter certificate and triggers a reboot of the vCenter server.

5. **List certificates for a hostname**:
   ```powershell
   .\RenewSslCertificates.ps1 -CAConfig "cahost\caname" -Hostname "server.example.com"
   ```
   This displays all certificates issued for the specified hostname, including expiry dates and templates.

6. **List certificates expiring within 30 days**:
   ```powershell
   .\RenewSslCertificates.ps1 -CAConfig "cahost\caname" -Days 30
   ```
   This lists certificates expiring within 30 days, with details logged to the file.

7. **List supported server types**:
   ```powershell
   .\RenewSslCertificates.ps1 -GetSupportedServerTypes
   ```
   This returns the list of supported server types (`Manual`, `WindowsMachine`, `iDRAC`, `vCenter`).

8. **Retrieve available certificate templates**:
   ```powershell
   .\RenewSslCertificates.ps1 -CAConfig "cahost\caname" -GetCATemplates
   ```
   This lists all certificate templates available on the specified CA.

### Functions

- `Get-CATemplates`: Retrieves available certificate templates from the CA.
- `Get-HostCertificates`: Displays certificates issued for a specific hostname.
- `Get-ExpiringCertificates`: Lists certificates expiring within a specified number of days.
- `Get-SupportedServerTypes`: Returns the list of supported server types.
- `Renew-Certificate`: Generates, submits, and installs certificates based on server type.

## Parameters

- `-CAConfig`: CA configuration string (e.g., "CAHost\CAName").
- `-CATemplate`: Certificate template name (e.g., "WebServer").
- `-Hostname`: Fully qualified domain name (FQDN) for the certificate.
- `-ServerType`: Type of server (`Manual`, `WindowsMachine`, `iDRAC`, `vCenter`).
- `-Credential`: PSCredential object for server authentication.
- `-CSRFile`: Path to the CSR file (for `Manual` type).
- `-CertFile`: Path to save the signed certificate (for `Manual` type).
- `-Organization`, `-OrganizationalUnit`, `-Locality`, `-State`, `-Country`: CSR subject details.
- `-KeyLength`: Key length for the certificate (default: 2048).

## Notes

- The script assumes the user has permissions to access the CA; separate CA credentials are not supported.
- Temporary files (e.g., CSR, INF) are created and cleaned up automatically.
- For `iDRAC`, the script uses `racadm` commands and requires a short delay for CSR generation.
- For `vCenter`, the VMware vCenter server will reboot after certificate installation.
- Logging: All actions, successes, and errors are logged to a timestamped file (e.g., `SSLCertManager_20250729.log`) in the script's directory for troubleshooting and auditing.

## Disclaimer

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of **MERCHANTABILITY** or **FITNESS FOR