rule Suspicious_Known_Attack_Tools
{
    meta:
        description = "Detects known attacker tools like Mimikatz, PowerSploit, Metasploit, LinPEAS, Chisel, SSH Backdoors, etc."
        author = "Othiam"
        date = "2024-02-20"
        reference = "https://attack.mitre.org"

    strings:
        // Windows Tools (Mimikatz, PowerSploit, Metasploit, etc.)
        $mimikatz1 = "mimikatz" nocase
        $mimikatz2 = "sekurlsa" nocase
        $mimikatz3 = "kerberos" nocase
        $powersploit1 = "PowerSploit" nocase
        $powersploit2 = "Invoke-Mimikatz" nocase
        $metasploit1 = "Meterpreter" nocase
        $metasploit2 = "metasploit" nocase
        $empire1 = "Empire" nocase
        $empire2 = "Stager" nocase
        $netcat1 = "nc.exe" nocase
        $netcat2 = "connect to" nocase
        $psexec1 = "psexec" nocase
        $common1 = "cmd.exe /c" nocase
        $common2 = "powershell -nop" nocase
        $common3 = "iex (New-Object Net.WebClient)" nocase

        // Linux Tools (LinPEAS, Chisel, etc.)
        $linpeas1 = "LinPEAS" nocase
        $linpeas2 = "linpeas.sh" nocase
        $chisel1 = "chisel" nocase
        $chisel2 = "ssh -L" nocase
        $weevely1 = "weevely" nocase
        $weevely2 = "php web shell" nocase
        $sshbackdoor1 = "sshd_config" nocase
        $sshbackdoor2 = "AuthorizedKeysFile" nocase
        $netcat3 = "nc -l" nocase
        $rat1 = "xorcist" nocase
        $rat2 = "nmap -sT" nocase

    condition:
        // Match any of the following:
        2 of ($mimikatz*) or
        1 of ($powersploit*) or
        1 of ($metasploit*) or
        1 of ($empire*) or
        1 of ($netcat*) or
        1 of ($psexec*) or
        2 of ($common*) or
        2 of ($linpeas*) or
        1 of ($chisel*) or
        1 of ($weevely*) or
        1 of ($sshbackdoor*) or
        2 of ($netcat3*) or
        1 of ($rat*)
}
