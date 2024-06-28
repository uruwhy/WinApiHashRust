// Reference: https://samrambles.com/guides/window-hacking-with-rust/creating-a-dll-with-rust/index.html
use windows::{
    Win32::Foundation::{HINSTANCE, HWND},
    Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH},
    Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK},
    core::PCWSTR,
};

// https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(h_inst_dll: HINSTANCE, reason: u32, _: *mut ()) -> bool {
    match reason {
        DLL_PROCESS_ATTACH | DLL_THREAD_ATTACH => spawn_message(),
        _ => (),
    }

    true
}

fn spawn_message() {
    unsafe {
        MessageBoxW(
            HWND(0),
            to_wstring("Injected message"),
            to_wstring("Injected DLL"),
            MB_OK,
        );
    }
}

fn to_wstring(value: &str) -> PCWSTR {
    let mut encoded = value.encode_utf16().collect::<Vec<_>>();
    encoded.push(0);
    PCWSTR::from_raw(encoded.as_ptr())
}
