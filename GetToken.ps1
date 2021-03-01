
function New-MS365AccessToken {
    <#
	.NOTES
    Author: https://adamtheautomator.com/microsoft-graph-api-powershell/
	#>
    PARAM(
        [string]$AppId = "3ae9b901-e781-43e6-a7c5-b99d892af7cc",
        [string]$CertificateThumbprint = "1AAF0E60C977BD4DEB6BF9511393BB06C5CD264B",
        [string]$Scope = "https://graph.microsoft.com/.default",
        [string]$TenantName = "common"
    )


    try {
        $Certificate = Get-Item Cert:\CurrentUser\My\$CertificateThumbprint -ErrorAction Stop
    }
    catch {
        Write-Error "Error retreiving certificate based on the provided thumbprint."
        $Certificate = $null
    }

    if($Certificate){
    $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

    # Create JWT timestamp for expiration
    $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)

    # Create JWT validity start timestamp
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)

    # Create JWT header
    $JWTHeader = @{
        alg = "RS256"
        typ = "JWT"
        x5t = $CertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
    }

    # Create JWT payload
    $JWTPayLoad = @{
        # What endpoint is allowed to use this JWT
        aud = "https://login.microsoftonline.com/$TenantName/oauth2/token"

        # Expiration timestamp
        exp = $JWTExpiration

        # Issuer = your application
        iss = $AppId

        # JWT ID: random guid
        jti = [guid]::NewGuid()

        # Not to be used before
        nbf = $NotBefore

        # JWT Subject
        sub = $AppId
    }

    # Convert header and payload to base64
    $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
    $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

    $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
    $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

    # Join header and Payload with "." to create a valid (unsigned) JWT
    $JWT = $EncodedHeader + "." + $EncodedPayload

    # Get the private key object of your certificate
    $PrivateKey = $Certificate.PrivateKey

    # Define RSA signature and hashing algorithm
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

    # Create a signature of the JWT
    $Signature = [Convert]::ToBase64String(
        $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)
    ) -replace '\+', '-' -replace '/', '_' -replace '='

    # Join the signature to the JWT with "."
    $JWT = $JWT + "." + $Signature

    # Create a hash with body parameters
    $Body = @{
        client_id             = $AppId
        client_assertion      = $JWT
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        scope                 = $Scope
        grant_type            = "client_credentials"

    }

    $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token"

    # Use the self-generated JWT as Authorization
    $Header = @{
        Authorization = "Bearer $JWT"
    }

    # Splat the parameters for Invoke-Restmethod for cleaner code
    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method      = 'POST'
        Body        = $Body
        Uri         = $Url
        Headers     = $Header
    }

    $Response = Invoke-RestMethod @PostSplat
    $Response
}
}



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


$result = New-MS365AccessToken
write-host "Your access token is: " $result