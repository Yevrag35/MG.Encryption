﻿#
# Module manifest for module 'StringCertProtection'
#
# Generated by: Mike Garvey
#
# Generated on: 6/19/2019
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'MG.Encryption.PowerShell.dll'

# Version number of this module.
ModuleVersion = '2.2.0'

# Supported PSEditions
CompatiblePSEditions = @('Desktop')

# ID used to uniquely identify this module
GUID = '17353e9a-7625-4340-a797-96cd9d9334f5'

# Author of this module
Author = 'Mike Garvey'

# Company or vendor of this module
CompanyName = 'Yevrag35, LLC.'

# Copyright statement for this module
Copyright = '© 2019 Yevrag35, LLC.  All rights reserved.'

# Description of the functionality provided by this module
Description = 'A set of cmdlets to encrypt/decrypt sensitive strings using certificate-based encryption methods.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.7'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @('MG.Dynamic.dll', 'MG.Encryption.dll')

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('StringCertCreation.psm1')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'New-StringCertificate'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = 'Protect-String', 'Protect-StringToRegistry', 'Unprotect-String', 
               'Unprotect-StringFromRegistry'

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = 'New-StringCert', 'nsc'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = @(
	'MG.Dynamic.dll',
	'MG.Encryption.dll',
	'MG.Encryption.PowerShell.dll',
	'StringCertCreation.psm1',
	'StringCertProtection.psd1'
)

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'Encryption', 'Certificate', 'SHA256', 'Protect', 'String', 'Encrypt', 
               'Decrypt', 'Module', 'Cmdlet', 'Credential', 'SecureString', 'Plain', 'Text', 
               'Unprotect', 'New', 'Generate', 'Registry', 'PSPath'

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/Yevrag35/MG.Encryption'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = 'Fixed byte length error resulting in "Index was outside of bounds" exceptions for certain length passwords.'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://github.com/Yevrag35/MG.Encryption/issues'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

