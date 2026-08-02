// EICAR antivirus test file — completely harmless industry-standard
// string used to safely verify AV detection works without real malware.
rule EICAR_Test_File {
    meta:
        description = "EICAR standard antivirus test file"
        severity    = 1
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
