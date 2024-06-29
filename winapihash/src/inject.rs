#[cfg(target_os = "windows")]

use hash_resolver::resolve_api;

// Perform classic DLL injection with GetProcAddress, OpenProcess, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread
// References: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/Inject.c
pub fn classic_dll_injection(pid: u32, dll_path: &str) {
    // Enable SE_PRIVILEGE_ENABLED for current process

    // Get handle to target process

    //
}
