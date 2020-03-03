[CmdletBinding()]
param
(
    [parameter(Mandatory=$true, Position=0)]
    [string] $DebugDirectory,

#    [parameter(Mandatory=$true, Position=1)]
#    [string] $ModuleFileDirectory,

    [parameter(Mandatory=$true, Position=2)]
    [string] $AssemblyInfo,

    [parameter(Mandatory=$true, Position=3)]
    [string] $TargetFileName
)

## Clear out files
Get-ChildItem -Path $DebugDirectory -Include *.ps1xml -Recurse | Remove-Item -Force;

## Get Module Version
$assInfo = Get-Content $AssemblyInfo;
foreach ($line in $assInfo)
{
    if ($line -like "*AssemblyFileVersion(*")
    {
        $vers = $line -replace '^\s*\[assembly\:\sAssemblyFileVersion\(\"(.*?)\"\)\]$', '$1';
    }
}
$allFiles = Get-ChildItem $ModuleFileDirectory -Include * -Exclude *.old -Recurse;
#$References = Join-Path "$ModuleFileDirectory\.." "Assemblies";
[string[]]$notIn = @('System.Management.Automation.dll', $TargetFileName)
[string[]]$References = Get-ChildItem -Path $DebugDirectory -Filter *.dll -File | Where { $_.Name -notin $notIn } | Select -ExpandProperty Name

#[string[]]$allDlls = Get-ChildItem $References -Include *.dll -Exclude 'System.Management.Automation.dll' -Recurse | Select -ExpandProperty Name;
#[string[]]$allFormats = $allFiles | ? { $_.Extension -eq ".ps1xml" } | Select -ExpandProperty Name;

$manifestFile = "StringCertProtection-Beta.psd1"

#$allFiles | Copy-Item -Destination $DebugDirectory -Force;

$manifest = @{
    Path               = $(Join-Path $DebugDirectory $manifestFile)
#    RealGuid          = '17353e9a-7625-4340-a797-96cd9d9334f5'
    Guid               = '17353e9a-7625-4340-a797-96cd9d9334f6'
    Description        = 'A set of cmdlets to encrypt/decrypt sensitive strings using certificate-based encryption methods.'
    Author             = 'Mike Garvey'
    CompanyName        = 'Yevrag35, LLC.'
    Copyright          = 'Copyright (c) 2019-2020 Yevrag35, LLC.  All rights reserved.'
    ModuleVersion      = $vers.Trim()
    DotNetFrameworkVersion = '4.7'
    PowerShellVersion  = '5.1'
    RootModule         = $TargetFileName
    NestedModules      = @('StringCertCreation.psm1')
#    RequiredAssemblies = @('System.Collections', 'System.Linq', 'System.Reflection')
    RequiredAssemblies = $References
    AliasesToExport    = @("New-StringCert", "nsc")
    CmdletsToExport    = '*'
    FunctionsToExport  = @('New-StringCertificate')
    VariablesToExport  = ''
    CompatiblePSEditions = 'Desktop'
#    FormatsToProcess   = if ($allFormats.Length -gt 0) { $allFormats } else { @() };
    ProjectUri	       = 'https://github.com/Yevrag35/MG.Encryption'
    Tags               = @( 'Encryption', 'Certificate', 'SHA256', 'Protect', 'String', 'Encrypt', 
                            'Decrypt', 'Module', 'Cmdlet', 'Credential', 'SecureString', 'Plain', 'Text', 
                            'Unprotect', 'New', 'Generate', 'Registry', 'PSPath' )
};

New-ModuleManifest @manifest;