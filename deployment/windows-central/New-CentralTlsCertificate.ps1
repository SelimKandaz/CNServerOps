[CmdletBinding()]
param(
    [string]$CentralRoot = 'C:\CNServerOps\Central',
    [string]$IpAddress = '10.1.10.51',
    [int]$ValidDays = 825
)
$ErrorActionPreference = 'Stop'
$tlsRoot = Join-Path $CentralRoot 'tls'
New-Item -ItemType Directory -Path $tlsRoot -Force | Out-Null
$certPath = Join-Path $tlsRoot 'central-cert.pem'
$keyPath = Join-Path $tlsRoot 'central-key.pem'
if ((Test-Path -LiteralPath $certPath) -or (Test-Path -LiteralPath $keyPath)) {
    throw 'TLS material already exists; rotate it explicitly rather than overwriting it.'
}
$rsa = [System.Security.Cryptography.RSA]::Create(3072)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$IpAddress",
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddIpAddress([System.Net.IPAddress]::Parse($IpAddress))
    $san.AddDnsName('cnserverops-central')
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true
        )
    )
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-5),
        [DateTimeOffset]::UtcNow.AddDays($ValidDays)
    )
    [System.IO.File]::WriteAllText($certPath, $certificate.ExportCertificatePem(), [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($keyPath, $rsa.ExportPkcs8PrivateKeyPem(), [System.Text.UTF8Encoding]::new($false))
} finally {
    $rsa.Dispose()
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$system = ([System.Security.Principal.SecurityIdentifier]'S-1-5-18').Translate([System.Security.Principal.NTAccount]).Value
$administrators = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([System.Security.Principal.NTAccount]).Value
$acl = [System.Security.AccessControl.FileSecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @($identity, $system, $administrators)) {
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $entry,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
}
Set-Acl -LiteralPath $keyPath -AclObject $acl
[pscustomobject]@{ status = 'CREATED'; certificate = $certPath; private_key = $keyPath; ip_san = $IpAddress }
