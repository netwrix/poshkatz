Import-Module (Join-Path $PSScriptRoot 'poshkatz.psd1') -Force

function Get-ADUser {

}

Describe "TabExpansion" {
    Context "Commands" {
        It "should expand commands" {
            $Result = poshkatz\TabExpansion -line 'mimikatz kerberos::l'
            $Result | Should be 'kerberos::list'
        }
    }

    Context "Parameters" {
        It "should expand parameters " {
            $Result = poshkatz\TabExpansion -line 'mimikatz kerberos::list /E'
            $Result | Should be '/Export'
        }
    }

    Context "Parameters with values" {
        It "should expand parameters with values" {
            Mock Get-ADUser { [PSCustomObject]@{ Name = "Administrator" } }
            $Result = poshkatz\TabExpansion -line 'mimikatz sekurlsa::pth /User:'
            $Result | Should be '/User:Administrator'
        }
    }
}