$mimikatzParams = @{
    'kerberos::ask' = '/target: /rc4 /des /aes128 /aes256 /tkt /export /nocache'
    'kerberos::clist' = '/export'
    'kerberos::decode' = '/rc4: /aes128: /aes256: /des: /in: /out: /offset: /size:'
    'kerberos::hash' = '/password: /user: /domain: /count:'
    'kerberos::list' = '/export'
    'kerberos::golden' = '/ptt /user: /domain: /des: /rc4: /aes128: /aes256: /service: /target: /krbtgt: /startoffset: /endin: /renewmax: /sid: /id: /groups: /sids: /claims: /rodc: /ticket:' #TODO: domain fqdn
    'sekurlsa::bkeys' = '/export'
    'sekurlsa::tickets' = '/export'
    'sekurlsa::pth' = '/user: /domain: /luid: /ntlm: /aes128: /aes256: /impersonate /run:'
    'crypto::certificates' = '/export /systemstore: /store: /silent /nokey'
    'crypto::certtohw' = '/store: /name: /csp: /pin:'
    'crypto::hash' = '/password: /user: /count:'
    'crypto::keys' = '/export /provider: /providerype: /cngprovider: /machine /silent'
    'crypto::scauth' = '/caname: /upn: /pfx: /castore: /hw /csp: /pin: /nostore /crldp:' #TODO
    'crypto::stores' = '/systemstore:'
    'crypto::system' = '/export /file:'
    'dpapi::blob' = '/in: /out: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::cache' = '/file: /flush /load /save'
    'dpapi::capi' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::chrome' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::cng' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::cred' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::credhist' = '/in: /sid: /password: /sha1:'
    'dpapi::masterkey' = '/in: /protected /sid: /hash: /system: /password: /pvk: /rpc /dc: /domain:' # TODO: dc, domain
    'dpapi::protect' = '/data: /description: /entropy: /machine /system /prompt /c /out:'
    'dpapi::rdg' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::ssh' = '/hive: /impersonate /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::vault' = '/cred: /policy: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::wifi' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::wwan' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'lsadump::bkey' = '/system: /export /secret /guid:'
    'lsadump::cache' = '/user: /password: /ntlm: /subject: /system: /security:' # TODO:
    'lsadump::changentlm' = '/oldpassword: /oldntlm: /newpassword: /newntlm: /server: /user: /rid:' #TODO
    'lsadump::dcsync' = '/all /user: /guid: /domain: /dc: /altservice: /export /csv' #TODO: /dc:
    'lsadump::dcshadow' = '/object: /domain: /attribute: /value: /clean /multiple /replOriginatingUid: /replOriginatingUsn: /replOriginatingTime: /dynamic /dc: /computer: /push /stack /viewstack /clearstack /manualregister /manualpush /manualunregister /addentry /remotemodify /viewreplication /kill: /config /schema /root'
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
    'process::exports' = '/pid:'
    'process::imports' = '/pid:'
    'process::resume' = '/pid:'
    'process::runp' = '/run: /ppid: /token'
    'process::stop' = '/pid:'
    'process::suspend' = '/pid:'
    'rpc::server' = '/stop /protseq: /endpoint: /service: /alg: /noauth /ntlm /kerberos /noreg /secure /guid:' # TODO
    'rpc::connect' = '/server: /protseq: /endpoint: /service: /alg: /noauth /ntlm /kerberos /null /guid:' # TODO CALG_3DES = 3DES, Prot = ncacn_ip_tcp
    'sid::add' = '/sam: /sid: /new: /system:' # TODO: SAM, system
    'sid::clear' = '/sam: /sid: /system:' # TODO: SAM, system
    'sid::lookup' = '/sid: /name: /system:' # TODO: name, system
    'sid::modify' = '/sam: /sid: /new: /system:' # TODO: SAM, system
    'sid::query' = '/sam: /sid: /system:' # TODO: SAM, system
    'standard::base64' = '/in /out'
    'standard::log' = '/stop'
    'standard::version' = '/full /cab'
    'sysenv::del' = '/name: /guid: /attributes:'
    'sysenv::get' = '/name: /guid:'
    'sysenv::set' = '/name: /guid: /attributes: /data:'
    'token::elevate' = '/user: /id: /system /admin /domainadmin /enterpriseadmin'
    'token::list' = '/user: /id: /system /admin /domainadmin /enterpriseadmin'
    'token::run' = '/process: /user: /id:' #TODO: user
    'ts::remote' = '/id: /target: /password:'
    'ts::sessions' = '/server:'
    'vault::cred' = '/patch'
    'vault::list' = '/attributes'
}

$getUserScript = { Get-ADUser -Filter "Name -like '$($args[0])*'" }
$getCommandScript = { Get-Command -Name "$($args[0])*" -CommandType Application | Select-Object -ExpandProperty Name }
$getPidScript = { Get-Process | Select-Object -ExpandProperty Id | Sort-Object }
$getDomainScript = { Get-ADDomain | Where Name -Like "$($args[0])*" | Select-Object -Expand Name }

$mimikatzParamValues = @{
    'sekurlsa::pth' = @{
        'user' = $getUserScript
        'domain' = $getDomainScript
        'run' = { 'cmd.exe', 'mmc.exe' }
    }
    'kerberos::hash' = @{
        'count' = { 4096 }
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
        'domain' = $getDomainScript
        'altservice' = { 'ldap' }
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
    'process::exports' = @{
        'pid' = $getPidScript
    }
    'process::imports' = @{
        'pid' = $getPidScript
    }
    'process::resume' = @{
        'pid' = $getPidScript
    }
    'process::runp' = @{
        'run' = $getCommandScript
        'ppid' = $getPidScript
    }
    'process::stop' = @{
        'pid' = $getPidScript
    }
    'process::suspend' = @{
        'pid' = $getPidScript
    }
    'sysenv::del' = @{
        'name' = { 'Kernel_Lsa_Ppl_Config' } 
        'guid' = { '{77fa9abd-0359-4d32-bd60-28f4e78f784b}' }
        'attributes' = { '07' }
    }
    'sysenv::get' = @{
        'name' = { 'Kernel_Lsa_Ppl_Config' } 
        'guid' = { '{77fa9abd-0359-4d32-bd60-28f4e78f784b}' }
    }
    'sysenv::set' = @{
        'name' = { 'Kernel_Lsa_Ppl_Config' } 
        'guid' = { '{77fa9abd-0359-4d32-bd60-28f4e78f784b}' }
        'attributes' = { '07' }
        'data' = { '04' }
    }
    'token::run' = @{
        'process' = $getCommandScript
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
    'My',
    'Root',
    'Remote Desktop',
    'Trust',
    'CA',
    'TrustedPublisher',
    'ACRS',
    'ADDRESSBOOK',
    'AuthRoot',
    'ClientAuthIssuer',
    'Disallowed',
    'eSIM Certification Authorities',
    'FlightRoot',
    'Homegroup Machine Certificates',
    'ipcu',
    'Local NonRemovable Certificates',
    'REQUEST',
    'SmartCardRoot',
    'TestSignRoot',
    'TrustedDevices',
    'TrustedPeople',
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
    'Microsoft Smart Card Key Storage Provider',
    'Microsoft Platform Crypto Provider',
    'Microsoft Key Protection Provider',
    'Microsoft Passport Key Storage Provider',
    'Microsoft Primitive Provider',
    'Microsoft SSL Protocol Provider',
    'Windows Client Key Protection Provider'
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
