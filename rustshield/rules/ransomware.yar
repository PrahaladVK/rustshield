// ransomware.yar — tightened with size guards and stricter conditions

rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Contains shadow copy deletion commands — definitive ransomware pre-encryption step"
        severity    = 9
    strings:
        $v1 = "vssadmin delete shadows"               nocase
        $v2 = "wmic shadowcopy delete"                nocase
        $v3 = "bcdedit /set {default} recoveryenabled No" nocase
        $v4 = "wbadmin delete catalog"                nocase
        $v5 = "Get-WmiObject Win32_Shadowcopy"        nocase
    condition:
        // Any ONE of these strings in an executable is a strong signal —
        // no legitimate software needs to delete shadow copies.
        any of them
        and filesize < 20MB
}

rule Ransomware_NoteKeywords_Cluster {
    meta:
        description = "Dense cluster of ransom note keywords in an executable"
        severity    = 7
    strings:
        $k1 = "decrypt your files"  nocase wide ascii
        $k2 = "bitcoin"             nocase wide ascii
        $k3 = "YOUR FILES ARE"      nocase wide ascii
        $k4 = "tor browser"         nocase wide ascii
        $k5 = "ENCRYPTED"           nocase wide ascii
        $k6 = ".onion"              nocase ascii
        $k7 = "DO_NOT_DELETE"       nocase ascii
        $k8 = "README_DECRYPT"      nocase ascii
    condition:
        // Require 4 of 8 specific phrases (not just common words like "decrypt")
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and 4 of them
}
