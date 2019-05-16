$mimikatzParams = @{
    'kerberos::list' = '/export'
    'kerberos::golden' = '/admin: /domain: /sid: /krbtgt: /ticket:'
    'sekurlsa::tickets' = '/export'
    'sekurlsa::pth' = '/user: /domain: /ntlm: /run:'
    'crypto::certificates' = '/export /systemstore: /store: /silent /nokey'
    'crypto::certtohw' = '/store: /name: /csp: /pin:'
    'crypto::hash' = '/password: /user: /count:'
    'crypto::keys' = '/export /machine /provider: /providerype: /cngprovider: /silent'
    'crypto::scauth' = '/hw /csp: /pin: /nostore /castore: /caname: /upn: /crldp: /pfx:' #TODO
    'crypto::stores' = '/systemstore:'
    'crypto::system' = '/export /file:'
    'lsadump::bkey' = '/system: /export /secret /guid:'
    'lsadump::cache' = '/user: /password: /ntlm: /subject: /system: /security:' # TODO:
    'lsadump::changentlm' = '/oldpassword: /oldntlm: /newpassword: /newntlm: /server: /user: /rid:' #TODO
    'lsadump::dcsync' = '/user: /domain:'
    'lsadump::dcshadow' = '/object: /domain: /attribute: /value: /push'
    'lsadump::lsa' = '/patch /inject /id: /user:'
    'lsadump::netsync' = '/dc: /user: /ntlm: /account: /computer:'
    'lsadump::rpdata' = '/system: /name: /export /secret'
    'lsadump::sam' = '/system: /sam:'
    'lsadump::secrets' = '/system: /security:'
    'lsadump::setntlm' = '/password: /ntlm: /server: /user: /rid:' #TODO
    'lsadump::trust' = '/system: /patch'
    'acr::open' = '/trace'
    'busylight::single' = '/sound /color:'
    'event::clear' = '/log:'
    'iis::apphost' = '/live /in: /pvk:'
    'misc::skeleton' = '/letaes'
    'misc::wp' = '/file: /process:'
    'net::deleg' = '/dns /server:'
    'net::trust' = '/server:'
    'rpc::server' = '/stop /protseq: /endpoint: /service: /alg: /noauth /ntlm /kerberos /noreg /secure /guid:' # TODO
    'rpc::connect' = '/server: /protseq: /endpoint: /service: /alg: /noauth /ntlm /kerberos /null /guid:' # TODO CALG_3DES = 3DES, Prot = ncacn_ip_tcp
    'standard::base64' = '/in /out'
    'standard::log' = '/stop'
    'standard::version' = '/full /cab'
    'ts::remote' = '/id: /target: /password:'
    'ts::sessions' = '/server:'
}

$getUserScript = { Get-ADUser -Filter "Name -like '$($args[0])*'" }

$mimikatzParamValues = @{
    'sekurlsa::pth' = @{
        'user' = $getUserScript
    }
    'lsadump::cache' = @{
        'subject' = {
            Get-ChildItem -Path Cert:\CurrentUser\My |
                where Subject -like "*$($args[0])*" |
                Select-Object -ExpandProperty Subject
        }
    }
    'lsadump::dcsync' = @{
        'user' = $getUserScript
        'domain' = { Get-ADDomain | Where Name -Like "$($args[0])*" | Select-Object -Expand Name }
    }
    'lsadump::dcshadow' = @{
        'object' = { Get-ADObject -Filter "Name -like '$($args[0])*'" }
    }
    'lsadump::lsa' = @{
        'id' = { 500 }
        'user' = $getUserScript
    }
    'crypto::certificates' = @{ 
        'systemstore' = { $certSystemStoreLocations }
        'store' = { $certSystemStoreNames }
    }
    'crypto::certtohw' = @{
        'store' = { $certSystemStoreLocations }
        'csp' = { $capiProviders }
        'name' = {
            Get-ChildItem -Path cert:\ -Recurse |
                Where-Object { $PSItem.HasPrivateKey -and $PSItem.Subject -like "*$($args[0])*" } |
                Select-Object -ExpandProperty Subject
            }
    }
    'crypto::hash' = @{
        'user' = $getUserScript
        'count' = { 10240 }
    }
    'crypto::keys' = @{ 
        'provider' = { $capiProviders }
        'providertype' = { $capiProviderTypes }
        'cngprovider' = { $cngProviders }
    }
    'crypto::scauth' = @{
        'csp' = { $capiProviders }
        'castore' = { $certSystemStoreLocations }
    }
    'crypto::stores' = @{ 
        'systemstore' = { $certSystemStoreLocations }
    }
    'busylight::single' = @{
        'color' = { @('0xFF0000', '0x00FF00', '0x0000FF') }
    }
    'event::clear' = @{
        'log' = { Get-EventLog -List -AsString }
    }
    'misc::wp' = @{
        'process' = { 'explorer.exe' } # TODO: List valid processes
    }
}

$certSystemStoreLocations = @(
    'CURRENT_USER',
    'LOCAL_MACHINE',
    'CURRENT_SERVICE',
    'SERVICES',
    'USERS',
    'USER_GROUP_POLICY',
    'LOCAL_MACHINE_GROUP_POLICY',
    'LOCAL_MACHINE_ENTERPRISE'
)

$certSystemStoreNames = @(
    'ACRS',
    'ADDRESSBOOK',
    'AuthRoot',
    'CA',
    'ClientAuthIssuer',
    'Disallowed',
    'eSIM Certification Authorities',
    'FlightRoot',
    'Homegroup Machine Certificates',
    'Local NonRemovable Certificates',
    'My',
    'Remote Desktop',
    'REQUEST',
    'Root',
    'SmartCardRoot',
    'TestSignRoot',
    'Trust',
    'TrustedDevices',
    'TrustedPeople',
    'TrustedPublisher',
    'UserDS',
    'Windows Live ID Token Issuer'
)

$capiProviderTypes = @(
    'PROV_RSA_FULL',
    'PROV_RSA_AES',
    'PROV_RSA_SIG',
    'PROV_RSA_SCHANNEL',
    'PROV_DSS',
    'PROV_DSS_DH',
    'PROV_DH_SCHANNEL',
    'PROV_FORTEZZA',
    'PROV_MS_EXCHANGE',
    'PROV_SSL'
)

$capiProviders = @(
    'MS_DEF_DH_SCHANNEL_PROV',
    'MS_DEF_DSS_DH_PROV',
    'MS_DEF_DSS_PROV',
    'MS_DEF_PROV',
    'MS_DEF_RSA_SCHANNEL_PROV',
    'MS_DEF_RSA_SIG_PROV',
    'MS_ENH_DSS_DH_PROV',
    'MS_ENH_RSA_AES_PROV',
    'MS_ENHANCED_PROV',
    'MS_SCARD_PROV',
    'MS_STRONG_PROV'
)

$cngProviders = @(
    'Microsoft Software Key Storage Provider',
    'Microsoft Smart Card Key Storage Provider'
)

function script:cmdOperations($commands, $command, $filter) {
    $commands.$command -split ' ' | Where-Object { $_ -like "$filter*" }
}

function Get-MKModule {
    param($Filter)

    $Output = (mimikatz l::l exit) -join ([Environment]::NewLine)
    $Matches = [System.Text.RegularExpressions.RegEx]::Matches($Output, "(?:(?<Command>.*)\s+-\s(?<Help>.*))")
    $matches | Select-Object -Skip 1 | ForEach-Object -Process {
        [PSCustomObject]@{
            Name = $_.Captures.Groups[1].Value.Trim();
            Description = $_.Captures.Groups[2].Value.Trim()
        }
    } | Sort-Object -Property Name | Where-Object { $_.Name -like "$filter*" }
}

$script:modules = Get-MKModule | Select-Object -ExpandProperty Name

function Get-MKCommand {
    param(
        [string]$Module,
        [string]$Filter
    )

    $Output = (mimikatz "$Module::l" exit) -join ([Environment]::NewLine)
    $Matches = [System.Text.RegularExpressions.RegEx]::Matches($Output, "(?:(?<Command>.*)\s+-\s(?<Help>.*))")
    $matches | Select-Object -Skip 1 | ForEach-Object -Process {
        [PSCustomObject]@{
            Name = $_.Captures.Groups[1].Value.Trim();
            Description = $_.Captures.Groups[2].Value.Trim()
        }
    } | Sort-Object -Property Name | Where-Object { $_.Name -like "$filter*" }
}

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

function script:modules($filter) {
    Get-MKModule -Filter $filter | Select-Object -ExpandProperty Name | Sort-Object
}

function script:commands($module, $filter) {
    Get-MKCommand -Module $module -Filter $filter | Select-Object -ExpandProperty Name | ForEach-Object { "$module::$_" } | Sort-Object
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
    $aliases += "mimikatz.exe"
    "($($aliases -join '|'))"
 }

function TabExpansionInternal($lastBlock) {
    switch -regex ($lastBlock -replace "^$(Get-AliasPattern mimikatz) ","") {
        # Handles <cmd> (commands & aliases)
        "^`"?(?<module>\S*)$" {
            modules $matches['module']
        }

        "^`"?(?<cmd>\S*)::(?<value>\S*)$" {
            commands -Module $matches['cmd'] -Filter $matches['value']
        }

        # Handles gitCommands <cmd> /<param>:<value>
        "^`"?(?<cmd>$paramsWithValues).* /(?<param>[^=]+):(?<value>\S*)$" {
            expandParamValues $matches['cmd'] $matches['param'] $matches['value']
            return
        }

        # Handles mimikatz <cmd> /<param>
        "^`"?(?<cmd>$params).* /(?<param>\S*)$" {
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
