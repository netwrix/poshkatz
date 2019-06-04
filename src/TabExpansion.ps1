Set-StrictMode -Version Latest

#region Mimikatz Command Parameters
$mimikatzParams = @{
    '!+' = ''
    '!-' = ''
    '!ping' = ''
    '!bsod' = ''
    '!filters' = ''
    '!minifilters' = ''
    '!modules' = ''
    '!notifImage' = ''
    '!notifObject' = ''
    '!notifProcess' = ''
    '!notifReg' = ''
    '!notifThread' = ''
    '!process' = ''
    '!processPrivilege' = '/pid:'
    '!processProtect' = '/process: /pid: /remove'
    '!processToken' = '/from: /to:'
    '!sysenvdel' = '/name: /guid: /attributes:'
    '!sysenvset' = '/name: /guid: /attributes: /data:'
    '!ssdt' = ''
    'acr::open' = '/trace'
    'busylight::single' = '/sound /color:'
    'crypto::certificates' = '/export /systemstore: /store: /silent /nokey'
    'crypto::certtohw' = '/store: /name: /csp: /pin:'
    'crypto::hash' = '/password: /user: /count:'
    'crypto::keys' = '/export /provider: /providerype: /cngprovider: /machine /silent'
    'crypto::scauth' = '/caname: /upn: /pfx: /castore: /hw /csp: /pin: /nostore /crldp:'
    'crypto::stores' = '/systemstore:'
    'crypto::system' = '/export /file:'
    'dpapi::blob' = '/in: /out: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::cache' = '/file: /flush /load /save'
    'dpapi::capi' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::chrome' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::cng' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::cred' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::credhist' = '/in: /sid: /password: /sha1:'
    'dpapi::masterkey' = '/in: /protected /sid: /hash: /system: /password: /pvk: /rpc /dc: /domain:'
    'dpapi::protect' = '/data: /description: /entropy: /machine /system /prompt /c /out:'
    'dpapi::rdg' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::ssh' = '/hive: /impersonate /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::vault' = '/cred: /policy: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::wifi' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'dpapi::wwan' = '/in: /unprotect /masterkey: /password: /entropy: /prompt /machine'
    'event::clear' = '/log:'
    'iis::apphost' = '/live /in: /pvk:'
    'kerberos::ask' = '/target: /rc4 /des /aes128 /aes256 /tkt /export /nocache'
    'kerberos::clist' = '/export'
    'kerberos::decode' = '/rc4: /aes128: /aes256: /des: /in: /out: /offset: /size:'
    'kerberos::golden' = '/ptt /user: /domain: /des: /rc4: /aes128: /aes256: /service: /target: /krbtgt: /startoffset: /endin: /renewmax: /sid: /id: /groups: /sids: /claims: /rodc: /ticket:'
    'kerberos::hash' = '/password: /user: /domain: /count:'
    'kerberos::list' = '/export'
    'lsadump::bkey' = '/system: /export /secret /guid:'
    'lsadump::cache' = '/user: /password: /ntlm: /subject: /system: /security:'
    'lsadump::changentlm' = '/oldpassword: /oldntlm: /newpassword: /newntlm: /server: /user: /rid:'
    'lsadump::dcshadow' = '/object: /domain: /attribute: /value: /clean /multiple /replOriginatingUid: /replOriginatingUsn: /replOriginatingTime: /dynamic /dc: /computer: /push /stack /viewstack /clearstack /manualregister /manualpush /manualunregister /addentry /remotemodify /viewreplication /kill: /config /schema /root'
    'lsadump::dcsync' = '/all /user: /guid: /domain: /dc: /altservice: /export /csv'
    'lsadump::lsa' = '/patch /inject /id: /user:'
    'lsadump::netsync' = '/dc: /user: /ntlm: /account: /computer:'
    'lsadump::rpdata' = '/system: /name: /export /secret'
    'lsadump::sam' = '/system: /sam:'
    'lsadump::secrets' = '/system: /security:'
    'lsadump::setntlm' = '/password: /ntlm: /server: /user: /rid:'
    'lsadump::trust' = '/system: /patch'
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
    'rpc::connect' = '/server: /protseq: /endpoint: /service: /alg: /noauth /ntlm /kerberos /null /guid:'
    'rpc::server' = '/stop /protseq: /endpoint: /service: /noauth /ntlm /kerberos /noreg /secure /guid:'
    'sekurlsa::bkeys' = '/export'
    'sekurlsa::pth' = '/user: /domain: /luid: /ntlm: /aes128: /aes256: /impersonate /run:'
    'sekurlsa::tickets' = '/export'
    'sid::add' = '/sam: /sid: /new: /system:'
    'sid::clear' = '/sam: /sid: /system:'
    'sid::lookup' = '/sid: /name: /system:'
    'sid::modify' = '/sam: /sid: /new: /system:'
    'sid::query' = '/sam: /sid: /system:'
    'standard::base64' = '/in /out'
    'standard::log' = '/stop'
    'standard::version' = '/full /cab'
    'sysenv::del' = '/name: /guid: /attributes:'
    'sysenv::get' = '/name: /guid:'
    'sysenv::set' = '/name: /guid: /attributes: /data:'
    'token::elevate' = '/user: /id: /system /admin /domainadmin /enterpriseadmin'
    'token::list' = '/user: /id: /system /admin /domainadmin /enterpriseadmin'
    'token::run' = '/process: /user: /id:'
    'ts::remote' = '/id: /target: /password:'
    'ts::sessions' = '/server:'
    'vault::cred' = '/patch'
    'vault::list' = '/attributes'
}
#endregion Mimikatz Command Parameters

#region Mimikatz Parameter Values
$mimikatzParamValues = @{
    'busylight::single' = @{
        'color' = { @('0xFF0000', '0x00FF00', '0x0000FF') }
    }
    'crypto::certificates' = @{ 
        'systemstore' = { Expand-CertSystemStoreLocation -Filter $args[0] }
        'store' = { Expand-CertSystemStoreName -Filter $args[0] }
    }
    'crypto::certtohw' = @{
        'store' = { Expand-CertSystemStoreLocation -Filter $args[0] }
        'csp' = { Expand-CryptoApiProvider -Filter $args[0] }
        'name' = { Expand-CertSubject -Filter $args[0] -AllStores }
    }
    'crypto::hash' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'count' = { 10240 }
    }
    'crypto::keys' = @{ 
        'provider' = { Expand-CryptoApiProvider -Filter $args[0] }
        'providertype' = { Expand-CryptoApiProviderType -Filter $args[0] }
        'cngprovider' = { Expand-CngProvider -Filter $args[0] }
    }
    'crypto::scauth' = @{
        'csp' = { Expand-CryptoApiProvider -Filter $args[0] }
        'castore' = { Expand-CertSystemStoreLocation -Filter $args[0] }
        'upn' = { Expand-ADUserUPN -Filter $args[0] }
    }
    'crypto::stores' = @{ 
        'systemstore' = { Expand-CertSystemStoreLocation -Filter $args[0] }
    }
    'dpapi::masterkey' = @{ 
        'dc' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
        'domain' = { Expand-ADDomainFQDN -Filter $args[0] }
    }
    'event::clear' = @{
        'log' = { Expand-EventLogName -Filter $args[0] }
    }
    'kerberos::ask' = @{
        'target' = { Expand-KerberosSPNPrefix -Filter $args[0] | foreach { $PSItem + '/' } }
    }
    'kerberos::golden' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'domain' = { Expand-ADDomainFQDN -Filter $args[0] }
    }
    'kerberos::hash' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'domain' = { Expand-ADDomainFQDN -Filter $args[0] }
        'count' = { 4096 }
    }
    'lsadump::bkey' = @{
        'system' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'lsadump::cache' = @{
        'user' = { Expand-LocalUserName -Filter $args[0] }
        'subject' = { Expand-CertSubject -Filter $args[0] }
    }
    'lsadump::changentlm' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'server' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'lsadump::dcshadow' = @{
        'attribute' = { 'sIDHistory' }
        'domain' = { Expand-ADDomainFQDN -Filter $args[0] }
        'object' = { Expand-ADObjectDN -Filter $args[0] }
        'dc' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'lsadump::dcsync' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'domain' = { Expand-ADDomainFQDN -Filter $args[0] }
        'dc' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
        'altservice' = { Expand-KerberosSPNPrefix -Filter $args[0] }
    }
    'lsadump::lsa' = @{
        'id' = { 500 }
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
    }
    'lsadump::netsync' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'account' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'dc' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
        'computer' = { 'MIMIKATZ' }
    }
    'lsadump::rpdata' = @{
        'system' = { Expand-ADComputerFQDN -Filter $args[0] }
    }
    'lsadump::setntlm' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'server' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'lsadump::trust' = @{
        'system' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'misc::wp' = @{
        'process' = { Expand-ProcessName -Filter $args[0] }
    }
    'net::deleg' = @{
        'server' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'net::trust' = @{
        'server' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'process::exports' = @{
        'pid' = { Expand-ProcessId -Filter $args[0] }
    }
    'process::imports' = @{
        'pid' = { Expand-ProcessId -Filter $args[0] }
    }
    'process::resume' = @{
        'pid' = { Expand-ProcessId -Filter $args[0] }
    }
    'process::runp' = @{
        'run' = { Expand-WindowsCommand -Filter $args[0] }
        'ppid' = { Expand-ProcessId -Filter $args[0] }
    }
    'process::stop' = @{
        'pid' = { Expand-ProcessId -Filter $args[0] }
    }
    'process::suspend' = @{
        'pid' = { Expand-ProcessId -Filter $args[0] }
    }
    'rpc::connect' = @{
        'server' = { Expand-ADComputerFQDN -Filter $args[0] }
        'alg' = { '3DES' }
        'protseq' = { 'ncacn_ip_tcp', 'ncacn_http', 'ncacn_nb_tcp', 'ncacn_np' }
    }
    'rpc::server' = @{
        'protseq' = { 'ncacn_ip_tcp', 'ncacn_http', 'ncacn_nb_tcp', 'ncacn_np' }
    }
    'sekurlsa::pth' = @{
        'user' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'domain' = { Expand-ADDomainFQDN -Filter $args[0] }
        'run' = { 'cmd.exe', 'mmc.exe' }
    }
    'sid::add' = @{
        'sam' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'system' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'sid::clear' = @{
        'sam' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'system' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'sid::lookup'  = @{
        'name' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'system' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'sid::modify' = @{
        'sam' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'system' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
    }
    'sid::query' = @{
        'sam' = { Expand-ADUserSamAccountName -Filter $args[0] }
        'system' = { Expand-ADDomainControllerFQDN -Filter $args[0] }
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
    'token::elevate' = @{
        # TODO: 'user' Logged-on or AD?
    }
    'token::list' = @{
        'user' = { Expand-LoggedOnUserName -Filter $args[0] }
    }
    'token::run' = @{
        'user' = { Expand-LoggedOnUserName -Filter $args[0] }
        'process' = { Expand-WindowsCommand -Filter $args[0] }
    }
    'ts::sessions' = @{
        'server' = { Expand-ADComputerFQDN -Filter $args[0] }
    }
}

function Expand-CertSubject([string] $Filter, [switch] $AllStores) {
    # Returns certificates that have private keys from all stores or just the personal one.
    $path = 'cert:\'
    if($AllStores.IsPresent) {
        $path = 'Cert:\CurrentUser\My'
    }
    Get-ChildItem -Path $path -Recurse |
        Where-Object { $PSItem.HasPrivateKey -and $PSItem.Subject -like "*$Filter*" } |
        Select-Object -ExpandProperty Subject
}

function Expand-CertSystemStoreLocation([string] $Filter) {
    $locations = @(
        'CURRENT_USER',
        'LOCAL_MACHINE',
        'CURRENT_SERVICE',
        'SERVICES',
        'USERS',
        'USER_GROUP_POLICY',
        'LOCAL_MACHINE_GROUP_POLICY',
        'LOCAL_MACHINE_ENTERPRISE'
    )

    $locations | where { $PSItem -like "*$Filter*" }
}

function Expand-CertSystemStoreName([string] $Filter) {
    $stores = @(
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

    $stores | where { $PSItem -like "$Filter*" }
}

function Expand-CryptoApiProviderType([string] $Filter) {
    $providerTypes = @(
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

    $providerTypes | where { $PSItem -like "*$Filter*" }
}

function Expand-CryptoApiProvider([string] $Filter) {
    $providers = @(
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

    $providers | where { $PSItem -like "*$Filter*" }
}

function Expand-CngProvider([string] $Filter) {
    $providers = @(
        'Microsoft Software Key Storage Provider',
        'Microsoft Smart Card Key Storage Provider',
        'Microsoft Platform Crypto Provider',
        'Microsoft Key Protection Provider',
        'Microsoft Passport Key Storage Provider',
        'Microsoft Primitive Provider',
        'Microsoft SSL Protocol Provider',
        'Windows Client Key Protection Provider'
    )

    $providers | where { $PSItem -like "*$Filter*" }
}

function Expand-ADObjectDN([string] $Filter) {
    Get-ADObject -Filter { Name -like "$Filter*" } -ResultSetSize 10 |
        Select-Object -ExpandProperty DistinguishedName
}

function Expand-ADUserSamAccountName([string] $Filter) {
    Get-ADUser -Filter { SamAccountName -like "$Filter*" } -ResultSetSize 10 |
        Select-Object -ExpandProperty SamAccountName
}

function Expand-ADUserUPN([string] $Filter) {
    Get-ADUser -Filter { UserPrincipalName -like "$Filter*" } -ResultSetSize 10 |
        Select-Object -ExpandProperty UserPrincipalName
}

function Expand-ADComputerFQDN([string] $Filter) {
    Get-ADComputer -Filter { DNSHostName -like "$Filter*" } -Properties DNSHostName -ResultSetSize 10 |
        Select-Object -ExpandProperty DNSHostName
}

function Expand-ADDomainControllerFQDN([string] $Filter) {
    Get-ADDomainController -Filter { HostName -like "$Filter*" } | Select-Object -ExpandProperty HostName
}

function Expand-ADDomainFQDN([string] $Filter) {
    Get-ADDomain | Where-Object DNSRoot -Like "$Filter*" | Select-Object -ExpandProperty DNSRoot
}

function Expand-ADDomainNetBIOS([string] $Filter) {
    Get-ADDomain | Where-Object NetBIOSName -Like "$Filter*" | Select-Object -ExpandProperty NetBIOSName
}

function Expand-LocalUserName([string] $Filter) {
    Get-WmiObject -Class Win32_UserAccount -Filter "Name LIKE '$Filter%'" -Property Name | Select-Object -ExpandProperty Name
}

function Expand-LoggedOnUserName([string] $Filter) {
    Get-WmiObject -Class Win32_LoggedOnUser -Property Antecedent |
        foreach { $PSItem.Antecedent.Split('=')[2].Replace('"','') } |
        where {$PSItem -like "$Filter*"} |
        sort -Unique
}
function Expand-ProcessId([string] $Filter) {
    Get-Process |
        Where-Object { $PSItem.ProcessName -like "$Filter*" -or $PSItem.Id.ToString() -like "$Filter*" } |
        Select-Object -ExpandProperty Id
}

function Expand-ProcessName([string] $Filter) {
    Get-Process -Name "$Filter*" |
        Select-Object -ExpandProperty Name
}

function Expand-WindowsCommand([string] $Filter) {
    Get-Command -Name "$Filter*" -CommandType Application -TotalCount 10 |
        Select-Object -ExpandProperty Name
}

function Expand-KerberosSPNPrefix([string] $Filter) {
    $prefixes = @('cifs', 'ldap', 'host', 'rpcss', 'http', 'mssql', 'wsman')

    $prefixes | where { $PSItem -like "*$Filter*" }
}

function Expand-EventLogName([string] $Filter) {
    Get-EventLog -List -AsString |
        where { $PSItem -like "*$Filter*" }
}
#endregion Mimikatz Parameter Values

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

function script:expandParams($cmd, $filter) {
    $mimikatzParams[$cmd] -split ' ' |
        Where-Object { $_ -like "/$filter*" } |
        Sort-Object 
}

function script:expandParamValues($cmd, $param, $filter) {
    $mimikatzParamValues[$cmd][$param].Invoke($filter) |
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
