// Reference: https://samrambles.com/guides/window-hacking-with-rust/creating-a-dll-with-rust/index.html
use windows::{
    Win32::Foundation::{HINSTANCE, HWND},
    Win32::System::SystemServices::DLL_PROCESS_ATTACH,
    Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK},
    core::PCWSTR,
};

// https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(h_inst_dll: HINSTANCE, reason: u32, _: *mut ()) -> bool {
    match reason {
        DLL_PROCESS_ATTACH => spawn_message(),
        _ => (),
    }

    true
}

fn spawn_message() {
    let message_str_w = to_wstring("Injected msg");
    let title_str_w = to_wstring("Injected DLL");

    unsafe {
        MessageBoxW(
            HWND(0),
            PCWSTR::from_raw(message_str_w.as_ptr()),
            PCWSTR::from_raw(title_str_w.as_ptr()),
            MB_OK,
        );
    }
}

pub fn to_wstring(value: &str) -> Vec<u16> {
    return value.encode_utf16().chain([0u16]).collect::<Vec<u16>>();
}
