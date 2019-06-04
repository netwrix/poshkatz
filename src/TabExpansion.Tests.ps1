Import-Module (Join-Path $PSScriptRoot 'poshkatz.psd1') -Force

function Get-ADUser {

}

Describe "TabExpansion" {
    Context "Commands" {
        It "should expand commands" {
            $Result = poshkatz\TabExpansion -line 'mimikatz kerberos::l'
            $Result | Should be 'kerberos::list'
        }

        It "should expand undocumented commands" {
            # TODO: This functionality is not yet implemented
            $Result = poshkatz\TabExpansion -line 'mimikatz rpc::co'
            $Result | Should be 'rpc::connect'
        }
        
        It "should expand commands from the standard module" {
            # TODO: This functionality is not yet implemented
            $Result = poshkatz\TabExpansion -line 'mimikatz ver'
            $Result | Should be 'version'
        }

        It "should expand commands from the kernel module" {
            # TODO: This functionality is not yet implemented
            $Result = poshkatz\TabExpansion -line 'mimikatz !pro'
            $Result | Should be '!processProtect'
        }
    }

    Context "Parameters" {
        It "should expand parameters" {
            $Result = poshkatz\TabExpansion -line 'mimikatz kerberos::list /E'
            $Result | Should be '/Export'
        }

        It "should expand parameters from the standard module" {
            # TODO: This functionality is not yet implemented
            $Result = poshkatz\TabExpansion -line 'mimikatz version /f'
            $Result | Should be '/full'
        }

        It "should expand parameters from the kernel module" {
            $Result = poshkatz\TabExpansion -line 'mimikatz !processProtect /pro'
            $Result | Should be '/process'
        }
    }

    Context "Parameters with values" {
        It "should expand parameters with values" {
            # TODO: Mocking is currently broken
            Mock Get-ADUser { [PSCustomObject]@{ Name = "Administrator" } }
            $Result = poshkatz\TabExpansion -line 'mimikatz sekurlsa::pth /User:'
            $Result | Should be '/User:Administrator'
        }

        It "should expand names of logged on users" {
            $Result = poshkatz\TabExpansion -line 'mimikatz token::list /User:'
            $Result | Should match '/User:.+'
        }

        It "should expand process names" {
            $Result = poshkatz\TabExpansion -line 'mimikatz misc::wp /process:explo'
            $Result | Should be '/process:explorer'
        }

        It "should expand process IDs" {
            $Result = poshkatz\TabExpansion -line 'mimikatz process::imports /pid:'
            $Result | Should match "/pid:[0-9]+"
        }

        It "should expand process IDs from names" {
            $Result = poshkatz\TabExpansion -line 'mimikatz process::imports /pid:Idle'
            $Result | Should be '/pid:0'
        }

        It "should expand event log names" {
            $Result = poshkatz\TabExpansion -line 'mimikatz event::clear /log:Sec'
            $Result | Should be '/log:Security'
        }

        It "should expand kerberos SPN prefixes" {
            $Result = poshkatz\TabExpansion -line 'mimikatz lsadump::dcsync /altservice:ld'
            $Result | Should be '/altservice:ldap'
        }

        It "should expand certificate stores" {
            $Result = poshkatz\TabExpansion -line 'mimikatz crypto::certificates /store:TrustedPub'
            $Result | Should be '/store:TrustedPublisher'
        }

        It "should expand certificate store locations" {
            $Result = poshkatz\TabExpansion -line 'mimikatz crypto::certificates /systemstore:CURRENT_U'
            $Result | Should be '/systemstore:CURRENT_USER'
        }

        It "should expand available Windows command names" {
            $Result = poshkatz\TabExpansion -line 'mimikatz token::run /process:calc'
            $Result | Should be '/process:calc.exe'
        }
    }
}
