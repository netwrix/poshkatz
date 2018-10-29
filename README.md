poshkatz
==================
poshkatz is a PowerShell module for Mimikatz that has a number of cool features!

**Brought to you by:**  
[Adam Driscoll](https://poshtools.com/)  
[Lee Berg](https://leealanberg.com/)


## Features ##
* mimikatz tab expansion "autocomplete"
* cmdlets for mimikatz functioning as a wrapper of Mimikatz
* Convert Mimikatz output into PowerShell Objects

## Getting Started ##
1. Install git
1. Install posh-git
    > install-module posh-git
2. Build or Download a fresh copy of [mimikatz](https://github.com/gentilkiwi/mimikatz)
4. Import the poshkatz module
    > Import-Module poshkatz.psd1
5. Ensure mimikatz.exe is in your path
6. Have some fun
    > Get-MKLogonPassword
