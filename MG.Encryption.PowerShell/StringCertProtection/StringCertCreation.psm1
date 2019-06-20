Function New-StringCertificate()
{
    [CmdletBinding(PositionalBinding=$false, DefaultParameterSetName = "None")]
    [Alias("New-StringCert", "nsc")]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param
    (
        [parameter(Mandatory=$false, Position=0)]
        [string] $Subject = "$env:COMPUTERNAME - StringCert",

        [parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string] $FriendlyName = [string]::Empty,

        [parameter(Mandatory=$false)]
        [datetime] $ValidUntil = [datetime]::Now.AddYears(2),

        [parameter(Mandatory=$false)]
        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [string] $Algorithm = "SHA256",

        [parameter(Mandatory=$false)]
        [ValidateSet("2048", "4096", "8192", "16384")]
        [int] $KeyLength = 2048,

        [parameter(Mandatory=$false)]
        [ValidateSet("CurrentUser", "LocalMachine")]
        [string] $InstallAsTrusted,

        [parameter(Mandatory=$true, ParameterSetName='ExportPfx')]
        [ValidateScript({
            $_ -match '\.pfx$'
        })]
        [string] $ToPfxFile,

        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,
            ParameterSetName='ExportPfx')]
        [alias('Password')]
        [securestring] $PfxPassword
    )
    Process
    {
        if ($PSBoundParameters.ContainsKey("InstallAsTrusted") -and $InstallAsTrusted -eq "LocalMachine")
        {
            # Make sure PowerShell is elevated
            $myWinId = [System.Security.Principal.WindowsIdentity]::GetCurrent();
            $myPrinId = New-Object System.Security.Principal.WindowsPrincipal($myWinId);
            $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
            if (-not $myPrinId.IsInRole($adm))
            {
                throw "To install the certificate in the trusted machine store, PowerShell must be running as an Administrator!";
            }
        }

        if ($PSBoundParameters.ContainsKey("Subject") -and $Subject.StartsWith("CN=", $true, [cultureinfo]::CurrentCulture))
        {
            $Subject = $Subject.Substring(3);
        }

        $extsToAdd = New-Object 'System.Collections.Generic.List[object]';
        $extsToAdd.Add((setKU));
        $extsToAdd.Add((setEKU));
        $extsToAdd.Add((setBC));

        # Set Subject Name
        $subj = setSubjectName -CN $Subject;

        # Make private key
        $privKey = newPrivateKey -Length $KeyLength;

        # Create request
        $certReq = newCertRequest `
            -CertSubject $subj `
            -Validity $ValidUntil `
            -PrivateKey $privKey `
            -HashAlgorithm $Algorithm `
            -Extensions $extsToAdd;

        [byte[]]$newCertBytes = completeRequest -Request $certReq -FriendlyName $FriendlyName;

        $newCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($newCertBytes);
        Write-Output -InputObject $newCert;

        if ($PSBoundParameters.ContainsKey("InstallAsTrusted"))
        {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                [System.Security.Cryptography.X509Certificates.StoreName]::Root,
                [System.Security.Cryptography.X509Certificates.StoreLocation]"$InstallAsTrusted"
            );
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed);
            $store.Add($newCert);
            $store.Close();
            $store.Dispose();
        }

        if ($PSBoundParameters.ContainsKey("ToPfxFile"))
        {
            [byte[]]$pfxData = $newCert.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
                $PfxPassword
            );
            [System.IO.File]::WriteAllBytes($ToPfxFile, $pfxData);
        }
    }
}

#region KEY USAGE
Function setKU()
{
    [CmdletBinding()]
    param()

    $private:ku = New-Object -ComObject 'X509Enrollment.CX509ExtensionKeyUsage.1';
    $private:ku.InitializeEncode(48);    # "DataEncipherment & KeyEncipherment"
    $private:ku.Critical = $false;
    return $private:ku;
}

#endregion

#region ENHANCED KEY USAGE
Function setEKU()
{
    [CmdletBinding()]
    param()

    $private:ekuOids = New-Object -ComObject 'X509Enrollment.CObjectIds.1';
    $private:serverAuthOid = New-Object -ComObject 'X509Enrollment.CObjectId.1';
    $private:clientAuthOid = New-Object -ComObject 'X509Enrollment.CObjectId.1';
    $private:sa = [System.Security.Cryptography.Oid]::FromFriendlyName("Server Authentication", [System.Security.Cryptography.OidGroup]::EnhancedKeyUsage);
    $private:ca = [System.Security.Cryptography.Oid]::FromFriendlyName("Client Authentication", [System.Security.Cryptography.OidGroup]::EnhancedKeyUsage);
    $private:serverAuthOid.InitializeFromValue($private:sa.Value);
    $private:clientAuthOid.InitializeFromValue($private:ca.Value);
    $private:ekuOids.Add($private:serverAuthOid);
    $private:ekuOids.Add($private:clientAuthOid);

    $private:ekuExt = New-Object -ComObject 'X509Enrollment.CX509ExtensionEnhancedKeyUsage.1';
    $private:ekuExt.InitializeEncode($private:ekuOids);
    return $private:ekuExt;
}

#endregion

#region BASIC CONSTRAINTS
Function setBC()
{
    [CmdletBinding()]
    param()

    $private:bc = New-Object -ComObject 'X509Enrollment.CX509ExtensionBasicConstraints.1';
    $private:bc.InitializeEncode($false, -1);
    $private:bc.Critical = $true;
    return $private:bc;
}

#endregion

#region SUBJECT NAME
Function setSubjectName([string] $CN)
{
    $private:name = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName.1';
    $private:name.Encode("CN=$($CN)", 0);
    return $private:name;
}

#endregion

#region PRIVATE KEY
Function newPrivateKey([int]$Length)
{
    $private:key = New-Object -ComObject 'X509Enrollment.CX509PrivateKey.1';
    $private:algId = New-Object -ComObject 'X509Enrollment.CObjectId.1';
    $private:algVal = [System.Security.Cryptography.Oid]::FromFriendlyName("RSA", [System.Security.Cryptography.OidGroup]::PublicKeyAlgorithm);
    $private:algId.InitializeFromValue($private:algVal.Value);
    $private:key.ProviderName = 'Microsoft RSA SChannel Cryptographic Provider';
    $private:key.Algorithm = $private:algId;
    $private:key.KeySpec = 1;   # 1 = 'XCN_AT_KEYEXCHANGE'
    $private:key.Length = $Length;
    $private:key.ExportPolicy = 1;  # 1 = 'XCN_NCRYPT_ALLOW_EXPORT_FLAG' -- (i.e. - You can export it :P )
    $private:key.MachineContext = $false;

    $private:key.Create();
    return $private:key;
}

#endregion

#region NEW CERT REQUEST
Function newCertRequest()
{
    param
    (
        [object] $CertSubject,
        [datetime] $Validity,
        [object] $PrivateKey,
        [string] $HashAlgorithm,
        [System.Collections.Generic.List[object]] $Extensions
    )

    $private:req = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCertificate.1';
    $private:req.InitializeFromPrivateKey(1, $PrivateKey, [string]::Empty);     # 1 = 'X509CertificateEnrollmentContext.CurrentUser'
    $private:req.Subject = $CertSubject;
    $private:req.Issuer = $private:req.Subject;
    $private:req.NotBefore = [datetime]::Now;
    $private:req.NotAfter = $Validity;
    foreach ($ext in $Extensions)
    {
        $private:req.X509Extensions.Add($ext);
    }
    $private:sigId = New-Object -ComObject 'X509Enrollment.CObjectId.1';
    $private:hash = [System.Security.Cryptography.Oid]::FromFriendlyName($HashAlgorithm, [System.Security.Cryptography.OidGroup]::HashAlgorithm);
    $private:sigId.InitializeFromValue($private:hash.Value);

    $private:req.SignatureInformation.HashAlgorithm = $private:sigId;
    $private:req.Encode();
    return $private:req;
}

#endregion

#region COMPLETE CERT REQUEST
Function completeRequest([object]$Request, [string]$FriendlyName)
{
    $private:enroll = New-Object -ComObject 'X509Enrollment.CX509Enrollment.1';
    if (-not [string]::IsNullOrEmpty($FriendlyName))
    {
        $private:enroll.CertificateFriendlyName = $FriendlyName;
    }
    $private:enroll.InitializeFromRequest($Request);

    $private:endCert = $private:enroll.CreateRequest(1);    # 1 = 'EncodingType.XCN_CRYPT_STRING_BASE64'
    $private:enroll.InstallResponse(2, $private:endCert, 1, [string]::Empty);
        # 2 = 'InstallResponseRestrictionFlags.AllowUntrustedCertificate'
        # 1 = 'EncodingType.XCN_CRYPT_STRING_BASE64'

    [byte[]]$private:certBytes = [System.Convert]::FromBase64String($private:endCert);
    Write-Output -InputObject $private:certBytes -NoEnumerate;
}

#endregion