if (Get-Module poshkatz) { return }

$psv = $PSVersionTable.PSVersion

. $PSScriptRoot\Commands.ps1
. $PSScriptRoot\Utils.ps1
. $PSScriptRoot\TabExpansion.ps1

$exportModuleMemberParams = @{
    Function = @(
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
        "ConvertFrom-MKOutput",
        'Invoke-MKDcShadow',
        "Get-MKModule",
        "Get-MKCommand"
    )
}

Export-ModuleMember @exportModuleMemberParams
