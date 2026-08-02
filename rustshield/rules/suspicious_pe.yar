// suspicious_pe.yar — tightened rules to minimise false positives.
// Each rule now requires the FULL set of indicators, not "any of them",
// and includes size/header guards.

rule Suspicious_ProcessInjection_Full_Triad {
    meta:
        description = "PE imports the complete classic injection triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"
        severity    = 9
        // Note: requires ALL THREE — security tools that use one or two legitimately won't fire
    strings:
        $va  = "VirtualAllocEx"      ascii
        $wpm = "WriteProcessMemory"  ascii
        $crt = "CreateRemoteThread"  ascii
        $op  = "OpenProcess"         ascii
    condition:
        uint16(0) == 0x5A4D        // MZ header
        and filesize > 4KB
        and filesize < 10MB        // large files are usually legitimate installers
        and all of ($va, $wpm, $crt, $op)
}

rule Suspicious_AntiDebug_MultipleChecks {
    meta:
        description = "PE uses multiple anti-debugging techniques together — single checks appear in legitimate apps"
        severity    = 5
    strings:
        $a = "IsDebuggerPresent"           ascii
        $b = "CheckRemoteDebuggerPresent"  ascii
        $c = "NtQueryInformationProcess"   ascii
    condition:
        uint16(0) == 0x5A4D
        and filesize > 4KB
        and all of them   // require ALL three — one alone is normal
}

rule Suspicious_CredentialDumping_LSASS {
    meta:
        description = "PE references LSASS combined with credential-dumping APIs"
        severity    = 8
    strings:
        $lsass    = "lsass"                       nocase ascii wide
        $logon    = "LsaEnumerateLogonSessions"   ascii
        $sekurlsa = "sekurlsa"                    nocase ascii
        $cred     = "SamQueryInformationUser"     ascii
    condition:
        uint16(0) == 0x5A4D
        and filesize > 4KB
        and $lsass
        and 1 of ($logon, $sekurlsa, $cred)   // lsass string + at least one dump API
}

rule Suspicious_PowerShell_Downloader {
    meta:
        description = "Script or binary contains PowerShell download cradle — requires multiple indicators"
        severity    = 7
    strings:
        $ps1 = "DownloadString"      nocase ascii wide
        $ps2 = "IEX"                 ascii wide
        $ps3 = "Invoke-Expression"   nocase ascii wide
        $ps4 = "Net.WebClient"       nocase ascii wide
        $ps5 = "DownloadFile"        nocase ascii wide
        $ps6 = "System.Net.WebClient" nocase ascii wide
    condition:
        filesize < 2MB       // large files unlikely to be a cradle script
        and 3 of them        // need 3 of 6 — 1-2 can appear in legitimate PowerShell scripts
}
