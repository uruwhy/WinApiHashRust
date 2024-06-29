#[cfg(target_os = "windows")]

use hash_resolver::resolve_api;

// References: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/Inject.c
pub fn reflective_dll_injection(pid: u32, dll_path: &str) {
    // Enable SE_PRIVILEGE_ENABLED for current process

    // Get handle to target process

    //
}
