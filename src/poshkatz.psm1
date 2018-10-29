param([switch]$NoVersionWarn,[switch]$ForcePoshGitPrompt)



if (Get-Module posh-git) { return }

$psv = $PSVersionTable.PSVersion

if ($psv.Major -lt 3 -and !$NoVersionWarn) {
    Write-Warning ("posh-git support for PowerShell 2.0 is deprecated; you have version $($psv).`n" +
    "To download version 5.0, please visit https://www.microsoft.com/en-us/download/details.aspx?id=50395`n" +
    "For more information and to discuss this, please visit https://github.com/dahlbyk/posh-git/issues/163`n" +
    "To suppress this warning, change your profile to include 'Import-Module posh-git -Args `$true'.")
}

& $PSScriptRoot\CheckVersion.ps1 > $null

. $PSScriptRoot\Commands.ps1
. $PSScriptRoot\Utils.ps1
. $PSScriptRoot\GitUtils.ps1
. $PSScriptRoot\GitParamTabExpansion.ps1
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
        'Get-AliasPattern'
    )
}

Export-ModuleMember @exportModuleMemberParams
