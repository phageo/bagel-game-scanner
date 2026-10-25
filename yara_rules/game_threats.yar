/*
   Starter YARA signatures for the Game Safety Scanner.

   Copy this file (or your own .yar / .yara files) into the YARA folder shown
   in Settings - by default  %USERPROFILE%\.game_safety_scanner\yara

   meta fields the scanner understands:
     description  shown as the finding title
     severity     LOW | MEDIUM | HIGH | CRITICAL   (or  score = 0..100)
     category     EXECUTION, OBFUSCATION, PROCESS, NETWORK, FILESYSTEM,
                  PERSISTENCE, CREDENTIALS, INPUT_CAPTURE, PACKING, EVASION
     confidence   0.0 - 1.0
*/

rule Discord_Token_Stealer_Strings
{
    meta:
        description = "Discord token stealer strings"
        severity = "CRITICAL"
        category = "CREDENTIALS"
        confidence = "0.85"
    strings:
        $path1 = "Local Storage\\leveldb" nocase ascii wide
        $path2 = "discordcanary" nocase ascii wide
        $rx    = /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/
        $hook  = "discord.com/api/webhooks" nocase ascii wide
        $hook2 = "discordapp.com/api/webhooks" nocase ascii wide
    condition:
        any of ($hook*) and (any of ($path*) or $rx)
}

rule Packed_UPX_Executable
{
    meta:
        description = "UPX-packed Windows executable"
        severity = "MEDIUM"
        category = "PACKING"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $sig  = "UPX!"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute cradle"
        severity = "HIGH"
        category = "EXECUTION"
    strings:
        $iex  = "IEX" nocase fullword ascii wide
        $iex2 = "Invoke-Expression" nocase ascii wide
        $dl1  = "DownloadString" nocase ascii wide
        $dl2  = "DownloadFile" nocase ascii wide
        $dl3  = "Invoke-WebRequest" nocase ascii wide
    condition:
        filesize < 2MB and any of ($iex*) and any of ($dl*)
}

rule Embedded_PE_In_Non_Executable
{
    meta:
        description = "Windows executable embedded inside another file"
        severity = "MEDIUM"
        category = "EVASION"
    strings:
        $stub = "This program cannot be run in DOS mode"
    condition:
        uint16(0) != 0x5A4D and $stub
}
