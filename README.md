# WinApiHashRust
Windows API hashing POC in Rust. Uses Windows API hashing to hide certain Windows API calls from the compiled binary's IAT.

Uses classic DLL injection to demonstrate API hashing and dynamic API resolution at run-time.

Additional notes/features:
- Uses DJB2 hash algorithm
- Hash and API resolution functionality broken out into separate libraries for easy reuse in other projects
- Provides stub DLL for injection

## References
- [Windows API Hashing in Malware](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware)
- [PE Internals Part 1: A few words about Export Address Table (EAT)](https://ferreirasc.github.io/PE-Export-Address-Table/)
- [Windows API resolution via hashing](https://github.com/LloydLabs/Windows-API-Hashing)
- [A dive into the PE file format](https://0xrick.github.io/win-internals/pe1/)
