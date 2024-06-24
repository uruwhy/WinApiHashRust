#[cfg(target_os = "windows")]

use std::error::Error;
use std::ffi::CStr;
use {
    windows::core::PCWSTR,
    windows::Win32::Foundation::{
        HMODULE,
        FreeLibrary,
    },
    windows::Win32::System::{
        LibraryLoader::LoadLibraryW,
        SystemServices::{
            IMAGE_DOS_HEADER,
            IMAGE_DOS_SIGNATURE,
            IMAGE_EXPORT_DIRECTORY,
            IMAGE_NT_SIGNATURE,
        },
        Diagnostics::Debug::{
            IMAGE_DIRECTORY_ENTRY_EXPORT,
            IMAGE_FILE_DLL,
            IMAGE_FILE_HEADER,
            IMAGE_NT_HEADERS64,
            IMAGE_OPTIONAL_HEADER64,
        },
    },
};


// Define return type for GetProcAddress
// Ref: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Foundation/type.FARPROC.html
pub type FARPROC = unsafe extern "system" fn() -> isize;

// Convert rust string to wide Windows string
// Reference: https://github.com/microsoft/windows-rs/issues/973
fn to_wstring(value: &str) -> PCWSTR {
    let mut encoded = value.encode_utf16().collect::<Vec<_>>();
    encoded.push(0);
    PCWSTR::from_raw(encoded.as_ptr())
}

fn release_hmodule(h_module: &HMODULE) {
    match unsafe { FreeLibrary(*h_module) } {
        Ok(_) => (),
        Err(e) => {
            println!("FreeLibrary failed: {}", e);
        }
    }
}

// Helper function to iterate through DLL EAT
// Reference: https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
// Reference: https://github.com/LloydLabs/Windows-API-Hashing/blob/master/resolve.c
fn process_module_eat(module_name: &str) -> Result<(), Box<dyn Error>> {
    println!("Processing module: {}", module_name);

    // Get module handle
    let module_name_w = to_wstring(module_name);
    let h_module: HMODULE = unsafe { LoadLibraryW(module_name_w)? };
    if h_module.is_invalid() {
        Err("LoadLibraryW returned invalid HMODULE.")?
    }

    // Save pointer to library base (HMODULE is DLL base address)
    let library_base_addr_val: isize = h_module.0;
    let library_base_ptr: *const u8 = library_base_addr_val as *const u8;

    // Read in DOS header
    let dos_header_ptr: *const IMAGE_DOS_HEADER = library_base_ptr as *const IMAGE_DOS_HEADER;

    // Debugging - display DOS header fields
    #[cfg(debug_assertions)]
    unsafe {
        println!("DOS header fields");
        println!("e_magic:    {:#06x}", (*dos_header_ptr).e_magic);
        println!("e_cblp:     {:#06x}", (*dos_header_ptr).e_cblp);
        println!("e_cp:       {:#06x}", (*dos_header_ptr).e_cp);
        println!("e_crlc:     {:#06x}", (*dos_header_ptr).e_crlc);
        println!("e_cparhdr:  {:#06x}", (*dos_header_ptr).e_cparhdr);
        println!("e_minalloc: {:#06x}", (*dos_header_ptr).e_minalloc);
        println!("e_maxalloc: {:#06x}", (*dos_header_ptr).e_maxalloc);
        println!("e_ss:       {:#06x}", (*dos_header_ptr).e_ss);
        println!("e_sp:       {:#06x}", (*dos_header_ptr).e_sp);
        println!("e_csum:     {:#06x}", (*dos_header_ptr).e_csum);
        println!("e_ip:       {:#06x}", (*dos_header_ptr).e_ip);
        println!("e_cs:       {:#06x}", (*dos_header_ptr).e_cs);
        println!("e_lfarlc:   {:#06x}", (*dos_header_ptr).e_lfarlc);
        println!("e_ovno:     {:#06x}", (*dos_header_ptr).e_ovno);
        println!("e_oemid:    {:#06x}", (*dos_header_ptr).e_oemid);
        println!("e_oeminfo:  {:#06x}", (*dos_header_ptr).e_oeminfo);

        // Bypass error for unaligned reference to packed field
        let lfanew: i32 = (*dos_header_ptr).e_lfanew;
        println!("e_lfanew:   {:#010x}", lfanew);
    }

    // Verify DOS header
    if unsafe { (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE } {
        release_hmodule(&h_module);
        Err("Invalid DOS header - magic number mismatch.")?
    }

    // Read in NT Headers
    let nt_headers_addr_val: isize = unsafe { library_base_addr_val + ((*dos_header_ptr).e_lfanew as isize) };
    let nt_headers_ptr: *const IMAGE_NT_HEADERS64 = nt_headers_addr_val as *const IMAGE_NT_HEADERS64;

    // Debugging - display NT headers fields
    #[cfg(debug_assertions)]
    unsafe {
        println!("NT Headers Signature:      {:#06x}", (*nt_headers_ptr).Signature);
        println!("NT headers FileHeader fields");
        println!("Machine:              {:#06x}", (*nt_headers_ptr).FileHeader.Machine.0);
        println!("NumberOfSections:     {:#06x}", (*nt_headers_ptr).FileHeader.NumberOfSections);
        println!("TimeDateStamp:        {:#06x}", (*nt_headers_ptr).FileHeader.TimeDateStamp);
        println!("PointerToSymbolTable: {:#10x}", (*nt_headers_ptr).FileHeader.PointerToSymbolTable);
        println!("NumberOfSymbols:      {:#10x}", (*nt_headers_ptr).FileHeader.NumberOfSymbols);
        println!("SizeOfOptionalHeader: {:#06x}", (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader);
        println!("Characteristics:      {:#06x}", (*nt_headers_ptr).FileHeader.Characteristics.0);
        println!("NT headers OptionalHeader fields");
        println!("Magic:                        {:#06x}", (*nt_headers_ptr).OptionalHeader.Magic.0);
        println!("MajorLinkerVersion:           {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorLinkerVersion);
        println!("MinorLinkerVersion:           {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorLinkerVersion);
        println!("SizeOfCode:                   {:#10x}", (*nt_headers_ptr).OptionalHeader.SizeOfCode);
        println!("SizeOfInitializedData:        {:#10x}", (*nt_headers_ptr).OptionalHeader.SizeOfInitializedData);
        println!("SizeOfUninitializedData:      {:#10x}", (*nt_headers_ptr).OptionalHeader.SizeOfUninitializedData);
        println!("AddressOfEntryPoint:          {:#10x}", (*nt_headers_ptr).OptionalHeader.AddressOfEntryPoint);
        println!("BaseOfCode:                   {:#10x}", (*nt_headers_ptr).OptionalHeader.BaseOfCode);

        // Note - this won't necessarily match what's in PE bear or other analysis tools
        let image_base: u64 = (*nt_headers_ptr).OptionalHeader.ImageBase;
        println!("ImageBase:                    {:#18x}", image_base);

        println!("SectionAlignment:             {:#10x}", (*nt_headers_ptr).OptionalHeader.SectionAlignment);
        println!("FileAlignment:                {:#10x}", (*nt_headers_ptr).OptionalHeader.FileAlignment);
        println!("MajorOperatingSystemVersion:  {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorOperatingSystemVersion);
        println!("MinorOperatingSystemVersion:  {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorOperatingSystemVersion);
        println!("MajorImageVersion:            {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorImageVersion);
        println!("MinorImageVersion:            {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorImageVersion);
        println!("MajorSubsystemVersion:        {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorSubsystemVersion);
        println!("MinorSubsystemVersion:        {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorSubsystemVersion);
        println!("Win32VersionValue:            {:#10x}", (*nt_headers_ptr).OptionalHeader.Win32VersionValue);
        println!("SizeOfImage:                  {:#10x}", (*nt_headers_ptr).OptionalHeader.SizeOfImage);
        println!("SizeOfHeaders:                {:#10x}", (*nt_headers_ptr).OptionalHeader.SizeOfHeaders);
        println!("CheckSum:                     {:#10x}", (*nt_headers_ptr).OptionalHeader.CheckSum);
        println!("Subsystem:                    {:#06x}", (*nt_headers_ptr).OptionalHeader.Subsystem.0);
        println!("DllCharacteristics:           {:#06x}", (*nt_headers_ptr).OptionalHeader.DllCharacteristics.0);

        // Bypass errors for unaligned reference to packed field
        let size_of_stack_reserve = (*nt_headers_ptr).OptionalHeader.SizeOfStackReserve;
        println!("SizeOfStackReserve:           {:#18x}", size_of_stack_reserve);

        let size_of_stack_commit = (*nt_headers_ptr).OptionalHeader.SizeOfStackCommit;
        println!("SizeOfStackCommit:            {:#18x}", size_of_stack_commit);

        let size_of_heap_reserve = (*nt_headers_ptr).OptionalHeader.SizeOfHeapReserve;
        println!("SizeOfHeapReserve:            {:#18x}", size_of_heap_reserve);

        let size_of_heap_commit = (*nt_headers_ptr).OptionalHeader.SizeOfHeapCommit;
        println!("SizeOfHeapCommit:             {:#18x}", size_of_heap_commit);

        println!("LoaderFlags:                  {:#10x}", (*nt_headers_ptr).OptionalHeader.LoaderFlags);
        println!("NumberOfRvaAndSizes:          {:#10x}", (*nt_headers_ptr).OptionalHeader.NumberOfRvaAndSizes);
        let mut index = 0;
        for image_data_directory in (*nt_headers_ptr).OptionalHeader.DataDirectory.iter() {
            println!("Data directory {} VirtualAddress: {:#10x}", index, image_data_directory.VirtualAddress);
            println!("Data directory {} Size:           {:#10x}", index, image_data_directory.Size);
            index = index + 1;
        }
    }

    // Verify NT headers
    if unsafe { (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE } {
        release_hmodule(&h_module);
        Err("Invalid NT headers - IMAGE_NT_SIGNATURE mismatch.")?
    }

    // Verify module is a DLL
    if unsafe { (*nt_headers_ptr).FileHeader.Characteristics & IMAGE_FILE_DLL != IMAGE_FILE_DLL } {
        release_hmodule(&h_module);
        Err("Module is not a DLL.")?
    }

    // Check that module has exports
    let export_dir_rva: u32 = unsafe { (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].VirtualAddress };
    let export_dir_size: u32 = unsafe { (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].Size };
    if export_dir_rva == 0 {
        release_hmodule(&h_module);
        Err("Could not find module's export directory: Null RVA.")?
    }
    if export_dir_size == 0 {
        release_hmodule(&h_module);
        Err("Could not find module's export directory: export size of 0.")?
    }

    // Access export directory
    let export_dir_addr_val: isize = library_base_addr_val + (export_dir_rva as isize);
    let export_dir_ptr: *const IMAGE_EXPORT_DIRECTORY = export_dir_addr_val as *const IMAGE_EXPORT_DIRECTORY;

    #[cfg(debug_assertions)]
    unsafe {
        println!("Export directory info:");
        println!("Base:                  {:#10x}", (*export_dir_ptr).Base);
        println!("NumberOfFunctions:     {:#10x}", (*export_dir_ptr).NumberOfFunctions);
        println!("NumberOfNames:         {:#10x}", (*export_dir_ptr).NumberOfNames);
        println!("AddressOfFunctions:    {:#10x}", (*export_dir_ptr).AddressOfFunctions);
        println!("AddressOfNames:        {:#10x}", (*export_dir_ptr).AddressOfNames);
        println!("AddressOfNameOrdinals: {:#10x}", (*export_dir_ptr).AddressOfNameOrdinals);
    }

    // Get the exported functions, exported names, and name ordinals.
    let exported_func_list_addr_val: isize = library_base_addr_val + unsafe { (*export_dir_ptr).AddressOfFunctions as isize };
    let exported_names_list_addr_val: isize = library_base_addr_val + unsafe { (*export_dir_ptr).AddressOfNames as isize };
    let exported_names_list_ptr: *const u32 = exported_names_list_addr_val as *const u32;
    let exported_ordinals_list_addr_val: isize = library_base_addr_val + unsafe { (*export_dir_ptr).AddressOfNameOrdinals as isize };

    // Iterate through exported function names. Note that we use NumberOfNames since we are only looking at functions
    // exported by name, not ordinal (NumberOfFunctions includes both)
    let num_names = unsafe {(*export_dir_ptr).NumberOfNames};
    println!("Traversing exported function names.");
    for i in 0..num_names {
        // Get function name. Each entry of AddressOfNames is an RVA for the exported name
        let func_name_rva: u32 = unsafe { *(exported_names_list_ptr.add(i as usize)) };
        let func_name_addr_val: isize = library_base_addr_val + func_name_rva as isize;
        let func_name_ptr: *const i8 = func_name_addr_val as *const i8;
        let func_name_cstr = unsafe { CStr::from_ptr(func_name_ptr) };

        #[cfg(debug_assertions)]
        match func_name_cstr.to_str() {
            Ok(s) => {
                println!("Found exported function {} with RVA {:#18x}", s, func_name_rva)
            },
            Err(e) => {
                println!("[ERROR] Failed to convert function name C-string to rust string: {}", e);
            }
        }

        // Check DJB2 hash of function name
    }

    Ok(())
}


fn main() {
    process_module_eat("kernel32.dll").unwrap();
}
