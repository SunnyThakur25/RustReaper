rule Common_Shellcode_Patterns {
    meta:
        description = "Detects common shellcode patterns such as XOR decryption, GetPC, and syscall instructions"
        author = "sunny thakur"
        date = "2025/06/22"
    strings:
        $xor_decrypt = { 80 30 ?? 40 }
        $get_pc = { E8 00 00 00 00 5? }
        $syscall = { 0F 05 }
    condition:
        any of them
}

rule PE_Header {
    meta:
        description = "Detects the presence of a Portable Executable (PE) header"
        author = "Your Name"
        date = "2025/06/22"
    strings:
        $mz = "MZ" ascii
        $pe = "PE\0\0" ascii
    condition:
        $mz at 0 and $pe at (uint32(@mz + 0x3C))
}

rule NOP_Sled {
    meta:
        description = "Detects a NOP sled"
        author = "Your Name"
        date = "2025/06/22"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
    condition:
        any of them
}
