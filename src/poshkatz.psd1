@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'poshkatz.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# ID used to uniquely identify this module
GUID = '2955894f-c454-46f8-875a-4e22891c1f1d'

# Author of this module
Author = 'Adam Driscoll and Lee Berg'

# Copyright statement for this module
Copyright = '(c) Adam Driscoll and Lee Berg'

# Description of the functionality provided by this module
Description = 'Provides mimikatz tab expansion and cmdlets'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Functions to export from this module
FunctionsToExport = @(
    'Export-MKKerberosTicket',
    'Get-MKCredentialVault',
    'Get-MKCredentialVaultCredential',
    'Get-MKKerberosTicket',
    'Get-MKLogonPassword',
    'Get-MKLsaCache',
    'Get-MKLsaSam',
    'Get-MKLsaSecret',
    'Get-MKTicket',
    'Grant-MKKerberosGoldenTicket',
    'Invoke-MKDcSync',
    'Invoke-MKPassTheHash',
    'TabExpansion',
    'Get-AliasPattern',
    'ConvertFrom-Mimi'
)

# Cmdlets to export from this module
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module
AliasesToExport = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess.
# This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{
        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('mimikatz', 'tab', 'tab-completion', 'tab-expansion', 'tabexpansion')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/stealthbits/poshkatz/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/stealthbits/poshkatz'

        # ReleaseNotes of this module
        ReleaseNotes = 'https://github.com/stealthbits/poshkatz/blob/master/CHANGELOG.MD'
    }

}

}
