#Requires -Version 4.0
[CmdletBinding(PositionalBinding=$false)]
param
(
	[Parameter(Mandatory)]
	[string] $Configuration,

	[Parameter(Mandatory)]
	[string] $ProjectName,

	[Parameter(Mandatory=$false)]
	[string] $NuspecFile
)

if ($Configuration -eq "Release")
{
	Function Private:Get-NuspecFile([string]$CurrentPath)
	{
		if (-not [string]::IsNullOrEmpty($CurrentPath))
		{
			$file = Get-ChildItem -Path $CurrentPath -Filter *.nuspec -File | Select-Object -First 1
			if ($null -ne $file)
			{
				$file.FullName
			}
		}
	}

	Import-Module "$PSScriptRoot\MG.NuGet.Nuspec.dll" -ErrorAction Stop;
	Set-Location $PSScriptRoot

	if (-not $PSBoundParameters.ContainsKey("NuspecFile"))
	{
		$NuspecFile = Private:Get-NuspecFile -CurrentPath $PSScriptRoot
	}

	if (-not [string]::IsNullOrEmpty($NuspecFile))
	{
		$editor = New-Object MG.NuGet.Nuspec.NuspecEditor($NuspecFile, "$PSScriptRoot\$ProjectName\Properties\AssemblyInfo.cs")
		$editor.Edit();

		& nuget.exe pack $NuspecFile -properties "Configuration=Release"
	}
}