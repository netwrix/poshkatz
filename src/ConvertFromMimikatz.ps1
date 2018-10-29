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
  
  
  
  function ConvertFrom-Mimi {
      param(
          [Parameter(Mandatory, ValueFromPipeline)]
          [string]$Output,
          [Parameter(Mandatory)]
          [ValidateSet("LogonPasswords", "VaultCred", "VaultList", "LsadumpSam")]
          [string]$OutputType
      )
  
      Process {
  
          switch($OutputType) {
              "LogonPasswords" { $RegEx = '(?:Authentication Id\s+:\s(?<AuthenticationId>.*))[\s\S]*?(?:Session\s+:\s(?<Session>.*))[\s\S]*?(?:User Name\s+:\s(?<UserName>.*))\r*\s*(?:Domain\s+:\s(?<Domain>.*))\r*\s*(?:Logon Server\s+:\s(?<LogonServer>.*))\r*\s*(?:Logon Time\s+:\s(?<LogonTime>.*))\r*\s*(?:SID\s+:\s(?<SID>.*))[\s\S]*?(?:NTLM\s*:\s(?<NTLMHash>.*))?[\s\S]*?(?:SHA1?\s*:\s(?<SHA1Hash>.*))?[\s\S]*?(?:Password\s*:\s(?<Password>.*))'}
              "VaultCred" { $RegEx = '(?:TargetName\s+:\s(?<TargetName>.*))[\s\S]*(?:UserName\s+:\s(?<UserName>.*))[\s\S]*(?:Comment\s+:\s(?<Comment>.*))[\s\S]*(?:Type\s+:\s(?<Type>.*))[\s\S]*(?:Persist\s+:\s(?<Persist>.*))[\s\S]*(?:Flags\s+:\s(?<Flags>.*))[\s\S]*(?:Credential\s+:\s(?<Credential>.*))[\s\S]*(?:Attributes\s+:\s(?<Attributes>.*))'}
              "VaultList" { $RegEx = '(?:Vault\s+:\s(?<Vault>.*))(?:\s+Name\s+:\s(?<Name>.*))(?:\s+Path\s+:\s(?<Path>.*))' }
              "LsadumpSam" {$RegEx = '(?:Domain\s+:\s(?<Domain>.*))[\s\S]*(?:SysKey\s+:\s(?<SysKey>.*))[\s\S]*(?:Local SID\s+:\s(?<LocalSID>.*))[\s\S]*(?:SAMKey\s+:\s(?<SAMKey>.*))'} 
          }
  
          $Output | ConvertTo-Object -Pattern $RegEx
      }
  }
  
  