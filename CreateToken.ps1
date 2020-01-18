function New-MS365AuthCert {
    param (
        [String]$TenantName = "irrelevant.url",
        [String]$CertOutputPath = "C:\Temp\PowerShellGraphCert.cer",
        [String]$StoreLocation = "Cert:\CurrentUser\My",
        [String]$ExpirationDate = (Get-Date).AddYears(2)
    )
    if (Test-Path $CertOutputPath) {
        
        $CreateCertificateSplat = @{
            FriendlyName      = "AzureApp"
            DnsName           = $TenantName
            CertStoreLocation = $StoreLocation
            NotAfter          = $ExpirationDate
            KeyExportPolicy   = "Exportable"
            KeySpec           = "Signature"
            Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
            HashAlgorithm     = "SHA256"
        }

        $Certificate = New-SelfSignedCertificate @CreateCertificateSplat
        $CertificatePath = Join-Path -Path $StoreLocation -ChildPath $Certificate.Thumbprint
        Export-Certificate -Cert $CertificatePath -FilePath $CertOutputPath | Out-Null
    }
    else {
        Write-Error "The save location for the certificate does not exist: $CertOutputPath"
    }

}
New-MS365AuthCert
