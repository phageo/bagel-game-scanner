"""Windows functions a standard Unity IL2CPP ``GameAssembly.dll`` imports.

Generated from the import tables of four real builds (the Cpp2IL project's
public test projects): Unity 2019.4.34, 2022.3.35, 6000.5.0a6 and 6000.6.0b1,
all 64-bit Windows. The table is their union. C# code never adds to an
IL2CPP program's import table - ``DllImport`` functions are looked up by
name at run time - so what is imported is what Unity's own runtime
(libil2cpp) needs, and it changes little between games.

``ws2_32.dll`` is in it with four functions (start-up, clean-up, last
error, send), ``advapi32.dll`` with the three calls for random numbers:
the baseline is per function, not per library.
"""
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/il2cpp_baseline.py")

IMPORTS = {
    "advapi32.dll": frozenset("""
        CryptAcquireContextW CryptGenRandom CryptReleaseContext
        EnumDynamicTimeZoneInformation EnumerateTraceGuidsEx EventActivityIdControl
        EventRegister EventSetInformation EventUnregister EventWrite EventWriteEx
        EventWriteString EventWriteTransfer GetDynamicTimeZoneInformationEffectiveYears
    """.split()),
    "bcrypt.dll": frozenset("""
        BCryptGenRandom
    """.split()),
    "dbghelp.dll": frozenset("""
        SymFromAddr SymInitialize
    """.split()),
    "iphlpapi.dll": frozenset("""
        GetAdaptersAddresses GetIfEntry GetNetworkParams
    """.split()),
    "kernel32.dll": frozenset(_IND[0].split()),
    "ole32.dll": frozenset("""
        CoCreateFreeThreadedMarshaler CoGetApartmentType CoGetContextToken CoInitializeEx
        CoTaskMemAlloc CoTaskMemFree CoUninitialize
    """.split()),
    "oleaut32.dll": frozenset("""
        #15 #16 #17 #19 #20 #23 #24 #6 #7 #77
    """.split()),
    "shell32.dll": frozenset("""
        SHGetFolderPathW SHGetKnownFolderPath
    """.split()),
    "user32.dll": frozenset("""
        MessageBoxA
    """.split()),
    "ws2_32.dll": frozenset("""
        #111 #115 #116 #19
    """.split()),
}
# Unity's own libraries and the WinRT API sets: any function of these is expected
OWN_LIBRARIES = ("baselib.dll", "api-ms-win-core-winrt-", "unityplayer.dll")
