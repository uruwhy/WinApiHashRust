# Windows API Hashing In Rust
Windows API hashing library and resources in Rust. Uses Windows API hashing dynamically resolve specified Windows API calls at runtime to to hide them from the compiled binary's IAT.

Additional notes/features:
- Uses DJB2 hash algorithm and macro to compute DJB2 hashes at build time.
- Hash and API resolution functionality broken out into separate libraries for easy reuse in other projects
- To reduce the number of times a module is loaded or parsed, the utility will resolve all desired imports
  from a given module as it is being processed

## Components
- `djb2/` - library that exports the `djb2_hash` function to calculate the DJB2 hash of a given `&[u8]` input slice.
- `djb2macro/` - library that exports the `djb2macro!` compile-time macro to calculate DJB2 hashes at build time
- `hash_resolver/` - library that performs the API hashing and dynamic resolution at run time.
  - `set_initial_target_apis` exported function sets which API functions to resolve
  - `resolve_api` exported function resolves the given API hash and module name, returning the function address as `u64`.
  - `addr_to_func_ptr` macro to convert an address (e.g. `u64`) to a function pointer (`*const ()`)
 
## Usage
Example code:
```Rust
use djb2macro::djb2;
use hash_resolver::*;

// Define the function type that we want to use
type FnMessageBoxW = fn(*mut c_void, *const u16, *const u16, u32) -> i32;
const MB_OK: u32 = 0x00000000;

// Set target APIs
// The djb2! macro will replace the strings with the corresponding hashes at build time.
// Any functions that you plan on dynamically resolving can be placed here
// for faster lookup
set_initial_target_apis(&[
    djb2!("OpenProcess"),
    djb2!("VirtualAllocEx"),
    djb2!("LoadLibraryW"),
    djb2!("WriteProcessMemory"),
    djb2!("CreateRemoteThread"),
    djb2!("MessageBoxW"),
    djb2!("CloseHandle"),
]).unwrap();

println!("Printing target hashes:");
print_target_hashes();

// Get function pointer for MessageBoxW
let message_box_w_ptr: FnMessageBoxW = addr_to_func_ptr!(resolve_api(djb2!("MessageBoxW"), "User32.dll").unwrap(), FnMessageBoxW);

// Call MessageBoxW
let message_str_w = to_wstring("Test msg");
let title_str_w = to_wstring("Test title");
let ret: i32 = message_box_w_ptr(0 as *mut c_void, message_str_w.as_ptr(), title_str_w.as_ptr(), MB_OK);
println!("MessageBoxW return value: {}", ret);
```

## Roadmap
- [ ] cache modules to avoid having to reload them in case of future lookups outside of initial scope
- [ ] XOR-crypt the addresses when storing them in memory and prior to using them

## References
- [Windows API Hashing in Malware](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware)
- [PE Internals Part 1: A few words about Export Address Table (EAT)](https://ferreirasc.github.io/PE-Export-Address-Table/)
- [Windows API resolution via hashing](https://github.com/LloydLabs/Windows-API-Hashing)
- [A dive into the PE file format](https://0xrick.github.io/win-internals/pe1/)
