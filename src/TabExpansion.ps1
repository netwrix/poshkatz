$mimikatzParams = @{
    'kerberos::list' = '/export'
    'kerberos::golden' = '/admin: /domain: /sid: /krbtgt: /ticket:'
    'sekurlsa::tickets' = '/export'
    'sekurlsa::pth' = '/user: /domain: /ntlm: /run:'
    'crypto::certificates' = '/export  /systemstore'
    'crypto::key' = '/export /machine'
    'lsadump::dcsync' = '/user: /domain:'
    'lsadump::dcshadow' = '/object: /domain: /attribute: /value: /push'
}

$mimikatzParamValues = @{
    'sekurlsa::pth' = @{
        'user' = { Get-ADUser -Filter "Name -like '$($args[0])*'" }
    }
    'lsadump::dcsync' = @{
        'user' = { Get-ADUser -Filter "Name -like '$($args[0])*'" }
    }
    'lsadump::dcshadow' = @{
        'object' = { Get-ADObject -Filter "Name -like '$($args[0])*'" }
    }
}

function script:cmdOperations($commands, $command, $filter) {
    $commands.$command -split ' ' | Where-Object { $_ -like "$filter*" }
}

$script:mimikatzCommands = @(
    'privilege::debug', 
    'sekurlsa::logonpasswords', 
    'sekurlsa::tickets', 
    'sekurlsa::pth', 
    'kerberos::list', 
    'kerberos::ptt', 
    'kerberos::golden',
    'vault::cred', 
    'vault::list', 
    'token::elevate', 
    'vault::cred', 
    'vault::list', 
    'lsadump::sam', 
    'lsadump::secrets', 
    'lsadump::cache',
    'lsadump::dcsync',
    'lsadump::dcshadow', 
    'token::revert')

$script:params = $mimikatzParams.Keys -join '|'
$script:paramsWithValues = $mimikatzParamValues.Keys -join '|'

filter quoteStringWithSpecialChars {
    if ($_ -and ($_ -match '\s+|#|@|\$|;|,|''|\{|\}|\(|\)')) {
        $str = $_ -replace "'", "''"
        "'$str'"
    }
    else {
        $_
    }
}

function script:commands($filter) {
        $cmdList = @()
        $cmdList += $script:mimikatzCommands  |
                Where-Object { $_ -like "$filter*" }

        $cmdList | Sort-Object
}

function script:adUsers($filter) {
    Get-ADUser -Filter "Name -like '%$filter%'"
}

function script:expandParams($cmd, $filter) {
    $mimikatzParams[$cmd] -split ' ' |
        Where-Object { $_ -like "/$filter*" } |
        Sort-Object 
}

function script:expandParamValues($cmd, $param, $filter) {
    $mimikatzParamValues[$cmd][$param].Invoke($filter) | Select-Object -ExpandProperty "Name" | 
    Sort-Object |
    ForEach-Object { -join ("/", $param, ":", $_) }
}

function Expand-Command($Command) {
    Invoke-Utf8ConsoleCommand { TabExpansionInternal $Command }
}

function Get-AliasPattern($exe) {
    $aliases = @($exe) + @(Get-Alias | Where-Object { $_.Definition -eq $exe } | Select-Object -Exp Name)
    "($($aliases -join '|'))"
 }

function TabExpansionInternal($lastBlock) {
    switch -regex ($lastBlock -replace "^$(Get-AliasPattern mimikatz) ","") {
        # Handles <cmd> (commands & aliases)
        "^(?<cmd>\S*)$" {
            commands $matches['cmd']
        }

        # Handles gitCommands <cmd> /<param>:<value>
        "^(?<cmd>$paramsWithValues).* /(?<param>[^=]+):(?<value>\S*)$" {
            expandParamValues $matches['cmd'] $matches['param'] $matches['value']
            return
        }

        # Handles mimikatz <cmd> /<param>
        "^(?<cmd>$params).* /(?<param>\S*)$" {
            expandParams $matches['cmd'] $matches['param']
        }
    }
}

$PowerTab_RegisterTabExpansion = if (Get-Module -Name powertab) { Get-Command Register-TabExpansion -Module powertab -ErrorAction SilentlyContinue }
if ($PowerTab_RegisterTabExpansion) {
    & $PowerTab_RegisterTabExpansion "mimikatz.exe" -Type Command {
        param($Context, [ref]$TabExpansionHasOutput, [ref]$QuoteSpaces)  # 1:

        $line = $Context.Line
        $lastBlock = [regex]::Split($line, '[|;]')[-1].TrimStart()
        $TabExpansionHasOutput.Value = $true
        Expand-Command $lastBlock
    }
    return
}

if (Test-Path Function:\TabExpansion) {
    Rename-Item Function:\TabExpansion TabExpansionBackup
}

function TabExpansion($line, $lastWord) {
    $lastBlock = [regex]::Split($line, '[|;]')[-1].TrimStart()

    switch -regex ($lastBlock) {
        # Execute git tab completion for all git-related commands
        "^$(Get-AliasPattern mimikatz) (.*)" { Expand-Command $lastBlock }

        # Fall back on existing tab expansion
        default {
            if (Test-Path Function:\TabExpansionBackup) {
                TabExpansionBackup $line $lastWord
            }
        }
    }
}
