@{
    RootModule = 'MG.Encryption.dll'
    GUID = '17353e9a-7625-4340-a797-96cd9d9334f5'
	# CompatiblePSEditions = @()
    Description = 'A set of cmdlets to encrypt/decrypt sensitive strings using certificate-based encryption methods.'
    Author = 'Mike Garvey'
    CompanyName = 'Yevrag35, LLC.'
    Copyright = '(c) 2019 Yevrag35, LLC.  All rights reserved.'
    ModuleVersion = '1.1.0'
    PowerShellVersion = '5.0'
	# PowerShellHostName = ''
	# PowerShellHostVersion = ''
	DotNetFrameworkVersion = '4.6.1'
	# RequiredModules = @()
    RequiredAssemblies = @(
		'System.Collections',
        'System.Net',
        'System.Security'
    )
	FunctionsToExport = 'New-StringCertificate'
	AliasesToExport = @('New-StringCert', 'nsc')
	# FormatsToProcess = @()
	# ScriptsToProcess = @()
	# TypesToProcess = @()
	CmdletsToExport = @(
		'Protect-String',
		'Unprotect-String'
	)
	NestedModules = @('StringCertCreation.psm1')
	VariablesToExport = ''
	FileList = @(
		'MG.Encryption.dll',
		'StringCertCreation.psm1',
		'StringCertProtection.psd1'
	)
	PrivateData = @{
		PSData = @{
			Tags = 'Encryption', 'Certificate', 'SHA256', 'Protect', 'String', 'Encrypt', 'Decrypt',
				'Module', 'Cmdlet', 'Credential', 'SecureString', 'Plain', 'Text', 'Unprotect', 'New', 'Generate'
			# LicenseUri = ''
			ProjectUri = 'https://git.yevrag35.com/gityev/mg.encryption.git'
			# IconUri = ''
			ReleaseNotes = 'Adds new function ''New-StringCert'' for easily creating a self-signed encryption certificate.'
		}
	}
}