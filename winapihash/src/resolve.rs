#[cfg(target_os = "windows")]

use std::collections::{HashSet, HashMap};
use std::error::Error;
use std::ffi::CStr;
use std::sync::Mutex;
use windows::Win32::{
    Foundation::{HMODULE, FreeLibrary},
    System::{
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
            IMAGE_NT_HEADERS64,
        },
    },
};
use djb2macro::djb2;
use crate::util::to_wstring;

// Macro to get pointer after adding RVA to base address.
macro_rules! ptr_from_rva {
    ($rva:expr, $base_addr:expr, $t:ty) => {
        ($base_addr + ($rva as isize)) as *const $t
    };
}

// APIs that we want to hash
lazy_static::lazy_static! {
    static ref TARGET_HASHES: Mutex<HashSet<u32>> = Mutex::new(
        HashSet::from([
            djb2!("Process32FirstW"),
            djb2!("CreateToolhelp32Snapshot"),
            djb2!("HeapAlloc"),
            djb2!("MessageBoxW"),
        ])
    );

    static ref HASHED_API_ADDRESSES: Mutex<HashMap<u32, u64>> = Mutex::new(HashMap::new());
}



fn release_hmodule(h_module: &HMODULE) {
    match unsafe { FreeLibrary(*h_module) } {
        Ok(_) => (),
        Err(e) => {
            println!("FreeLibrary failed: {}", e);
        }
    }
}

// Process forwarded export. Will check if the forwarded export API hash is not yet part of the target set.
// If it is not, the function will get the forwarded API hash and add it to the target hash list before
// processing the forwarded module EAT.
fn process_forwarded_export(forwarder: &str) -> Result<(), Box<dyn Error>> {
    println!("Processing forwarded export: {}", forwarder);

    // Parse out the destination DLL and API name
    let split: Vec<&str> = forwarder.split(".").collect();
    if split.len() != 2 || split[0].is_empty() || split[1].is_empty() {
        Err(format!("Invalid forwarder string: {}", forwarder))?
    }
    let dest_module_name = split[0];
    let dest_api_name = split[1];

    // Check new API hash
    let dest_api_hash: u32 = djb2::djb2_hash(dest_api_name.as_bytes());
    if resolved_api(&dest_api_hash)? {
        // We already resolved this API
        println!("Forwarding dest API {} already discovered - resolved to {}", dest_api_name, get_hashed_api_addr(&dest_api_hash)?);
        return Ok(());
    } else if !is_target_api(&dest_api_hash)? {
        // New API hash
        add_target_api(&dest_api_hash)?;
        println!("Adding forwarding dest API {} to target set with hash {}", dest_api_name, dest_api_hash);
    }

    let full_dest_module_name = dest_module_name.to_owned() + ".dll";
    match process_module_eat(&full_dest_module_name) {
        Ok(_) => {
            println!("Successfully processed forwarder module {}", full_dest_module_name);
            Ok(())
        },
        Err(e) => {
            Err(format!("Failed to process forwarder module {}: {}", full_dest_module_name, e))?
        }
    }
}

// Helper function to iterate through DLL EAT
// Reference: https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
// Reference: https://github.com/LloydLabs/Windows-API-Hashing/blob/master/resolve.c
fn process_module_eat(module_name: &str) -> Result<(), Box<dyn Error>> {
    #[cfg(debug_assertions)]
    println!("Processing module: {}", module_name);

    // Get module handle
    let module_name_w = to_wstring(module_name);
    let h_module: HMODULE = unsafe { LoadLibraryW(PCWSTR::from_raw(module_name_w.as_ptr()))? };
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
    let nt_headers_ptr: *const IMAGE_NT_HEADERS64 = ptr_from_rva!(unsafe {(*dos_header_ptr).e_lfanew}, library_base_addr_val, IMAGE_NT_HEADERS64);

    // Debugging - display NT headers fields
    #[cfg(debug_assertions)]
    unsafe {
        println!("NT Headers Signature:      {:#06x}", (*nt_headers_ptr).Signature);
        println!("NT headers FileHeader fields");
        println!("Machine:              {:#06x}", (*nt_headers_ptr).FileHeader.Machine.0);
        println!("NumberOfSections:     {:#06x}", (*nt_headers_ptr).FileHeader.NumberOfSections);
        println!("TimeDateStamp:        {:#06x}", (*nt_headers_ptr).FileHeader.TimeDateStamp);
        println!("PointerToSymbolTable: {:#010x}", (*nt_headers_ptr).FileHeader.PointerToSymbolTable);
        println!("NumberOfSymbols:      {:#010x}", (*nt_headers_ptr).FileHeader.NumberOfSymbols);
        println!("SizeOfOptionalHeader: {:#06x}", (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader);
        println!("Characteristics:      {:#06x}", (*nt_headers_ptr).FileHeader.Characteristics.0);
        println!("NT headers OptionalHeader fields");
        println!("Magic:                        {:#06x}", (*nt_headers_ptr).OptionalHeader.Magic.0);
        println!("MajorLinkerVersion:           {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorLinkerVersion);
        println!("MinorLinkerVersion:           {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorLinkerVersion);
        println!("SizeOfCode:                   {:#010x}", (*nt_headers_ptr).OptionalHeader.SizeOfCode);
        println!("SizeOfInitializedData:        {:#010x}", (*nt_headers_ptr).OptionalHeader.SizeOfInitializedData);
        println!("SizeOfUninitializedData:      {:#010x}", (*nt_headers_ptr).OptionalHeader.SizeOfUninitializedData);
        println!("AddressOfEntryPoint:          {:#010x}", (*nt_headers_ptr).OptionalHeader.AddressOfEntryPoint);
        println!("BaseOfCode:                   {:#010x}", (*nt_headers_ptr).OptionalHeader.BaseOfCode);

        // Note - this won't necessarily match what's in PE bear or other analysis tools
        let image_base: u64 = (*nt_headers_ptr).OptionalHeader.ImageBase;
        println!("ImageBase:                    {:#018x}", image_base);

        println!("SectionAlignment:             {:#010x}", (*nt_headers_ptr).OptionalHeader.SectionAlignment);
        println!("FileAlignment:                {:#010x}", (*nt_headers_ptr).OptionalHeader.FileAlignment);
        println!("MajorOperatingSystemVersion:  {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorOperatingSystemVersion);
        println!("MinorOperatingSystemVersion:  {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorOperatingSystemVersion);
        println!("MajorImageVersion:            {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorImageVersion);
        println!("MinorImageVersion:            {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorImageVersion);
        println!("MajorSubsystemVersion:        {:#06x}", (*nt_headers_ptr).OptionalHeader.MajorSubsystemVersion);
        println!("MinorSubsystemVersion:        {:#06x}", (*nt_headers_ptr).OptionalHeader.MinorSubsystemVersion);
        println!("Win32VersionValue:            {:#010x}", (*nt_headers_ptr).OptionalHeader.Win32VersionValue);
        println!("SizeOfImage:                  {:#010x}", (*nt_headers_ptr).OptionalHeader.SizeOfImage);
        println!("SizeOfHeaders:                {:#010x}", (*nt_headers_ptr).OptionalHeader.SizeOfHeaders);
        println!("CheckSum:                     {:#010x}", (*nt_headers_ptr).OptionalHeader.CheckSum);
        println!("Subsystem:                    {:#06x}", (*nt_headers_ptr).OptionalHeader.Subsystem.0);
        println!("DllCharacteristics:           {:#06x}", (*nt_headers_ptr).OptionalHeader.DllCharacteristics.0);

        // Bypass errors for unaligned reference to packed field
        let size_of_stack_reserve = (*nt_headers_ptr).OptionalHeader.SizeOfStackReserve;
        println!("SizeOfStackReserve:           {:#018x}", size_of_stack_reserve);

        let size_of_stack_commit = (*nt_headers_ptr).OptionalHeader.SizeOfStackCommit;
        println!("SizeOfStackCommit:            {:#018x}", size_of_stack_commit);

        let size_of_heap_reserve = (*nt_headers_ptr).OptionalHeader.SizeOfHeapReserve;
        println!("SizeOfHeapReserve:            {:#018x}", size_of_heap_reserve);

        let size_of_heap_commit = (*nt_headers_ptr).OptionalHeader.SizeOfHeapCommit;
        println!("SizeOfHeapCommit:             {:#018x}", size_of_heap_commit);

        println!("LoaderFlags:                  {:#010x}", (*nt_headers_ptr).OptionalHeader.LoaderFlags);
        println!("NumberOfRvaAndSizes:          {:#010x}", (*nt_headers_ptr).OptionalHeader.NumberOfRvaAndSizes);
        let mut index = 0;
        for image_data_directory in (*nt_headers_ptr).OptionalHeader.DataDirectory.iter() {
            println!("Data directory {:02} VirtualAddress: {:#010x}", index, image_data_directory.VirtualAddress);
            println!("Data directory {:02} Size:           {:#010x}", index, image_data_directory.Size);
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
    let export_dir_ptr: *const IMAGE_EXPORT_DIRECTORY = ptr_from_rva!(export_dir_rva, library_base_addr_val, IMAGE_EXPORT_DIRECTORY);

    #[cfg(debug_assertions)]
    unsafe {
        println!("Export directory info:");
        println!("Base:                  {:#010x}", (*export_dir_ptr).Base);
        println!("NumberOfFunctions:     {:#010x}", (*export_dir_ptr).NumberOfFunctions);
        println!("NumberOfNames:         {:#010x}", (*export_dir_ptr).NumberOfNames);
        println!("AddressOfFunctions:    {:#010x}", (*export_dir_ptr).AddressOfFunctions);
        println!("AddressOfNames:        {:#010x}", (*export_dir_ptr).AddressOfNames);
        println!("AddressOfNameOrdinals: {:#010x}", (*export_dir_ptr).AddressOfNameOrdinals);
    }

    // Get the exported functions, exported names, and name ordinals.
    let exported_func_list_ptr: *const u32 = ptr_from_rva!(unsafe {(*export_dir_ptr).AddressOfFunctions}, library_base_addr_val, u32);
    let exported_names_list_ptr: *const u32 = ptr_from_rva!(unsafe {(*export_dir_ptr).AddressOfNames}, library_base_addr_val, u32);
    let exported_ordinals_list_ptr: *const u16 = ptr_from_rva!(unsafe {(*export_dir_ptr).AddressOfNameOrdinals}, library_base_addr_val, u16);

    // Iterate through exported function names.
    // Note that we use NumberOfNames since we are only looking at functions
    // exported by name, not ordinal (NumberOfFunctions includes both)
    let num_names = unsafe {(*export_dir_ptr).NumberOfNames};

    #[cfg(debug_assertions)]
    println!("Traversing exported function names.");
    for i in 0..num_names {
        // Get function name. Each entry of AddressOfNames is an RVA for the exported name
        let func_name_rva: u32 = unsafe { *(exported_names_list_ptr.add(i as usize)) };
        let func_name_ptr: *const i8 = ptr_from_rva!(func_name_rva, library_base_addr_val, i8);
        let func_name_cstr = unsafe { CStr::from_ptr(func_name_ptr) };

        let func_name_str = match func_name_cstr.to_str() {
            Ok(s) => s,
            Err(e) => {
                Err(format!("[ERROR] Failed to convert API name C-string to rust string: {}", e))?
            }
        };

        // Check DJB2 hash of function name - if the API is one that we want, grab the address
        let hash: u32 = djb2::djb2_hash(func_name_cstr.to_bytes());
        if is_target_api(&hash)? {
            // Check if we already resolved this API
            if resolved_api(&hash)? {
                println!("Already resolved API {} with hash {:#010x}", func_name_str, hash);
                continue;
            }

            // Use the ordinal to get the API address
            let ordinal: u16 = unsafe { *(exported_ordinals_list_ptr.add(i as usize)) };
            let func_rva: u32 = unsafe { *(exported_func_list_ptr.add(ordinal as usize)) };
            let func_ptr: *const i8 =  ptr_from_rva!(func_rva, library_base_addr_val, i8);

            #[cfg(debug_assertions)]
            println!("Found target API {} with hash {:#010x} and RVA 0x{:x}", func_name_str, hash, func_rva);

            // Check if the address is a forwarder, meaning it's within the export directory
            if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                let forwarder_cstr = unsafe { CStr::from_ptr(func_ptr) };
                let forwarder_str =  match forwarder_cstr.to_str() {
                    Ok(s) => s,
                    Err(e) => {
                        Err(format!("[ERROR] Failed to convert API forwarder C-string to rust string: {}", e))?
                    }
                };
                println!("Found target API {} with hash {:#010x} and forwarder entry {}", func_name_str, hash, forwarder_str);

                // Process the forwarded export
                process_forwarded_export(&forwarder_str)?;
            } else {
                // Save the address
                let func_addr_to_save: u64 = func_ptr as u64;
                add_resolved_api(&hash, &func_addr_to_save)?;
                println!("Resolved target API {} with hash {:#010x} and address 0x{:x}", func_name_str, hash, func_addr_to_save);
            }
        }
    }

    Ok(())
}

#[cfg(debug_assertions)]
pub fn print_target_hashes() {
    for hash in TARGET_HASHES.lock().unwrap().clone().into_iter() {
        println!("{}", hash);
    }
}

// Checks if we already resolved the API with the corresponding hash
pub fn resolved_api(hash: &u32) -> Result<bool, Box<dyn Error>> {
    Ok(HASHED_API_ADDRESSES.lock()?.contains_key(hash))
}

// Checks if the given API hash belongs to an API that we are hashing
pub fn is_target_api(hash: &u32) -> Result<bool, Box<dyn Error>> {
    Ok(TARGET_HASHES.lock()?.contains(hash))
}

// Adds a new API as a target (e.g. when processing forwarded exports and the forwarded API name is different)
pub fn add_target_api(hash: &u32) -> Result<(), Box<dyn Error>> {
    TARGET_HASHES.lock()?.insert(*hash);
    Ok(())
}

// Marks the given API hash as resolved
pub fn add_resolved_api(hash: &u32, addr: &u64) -> Result<(), Box<dyn Error>> {
    HASHED_API_ADDRESSES.lock()?.insert(*hash, *addr);
    Ok(())
}

// Gets the address of the resolved API
pub fn get_hashed_api_addr(hash: &u32) -> Result<u64, Box<dyn Error>> {
    match HASHED_API_ADDRESSES.lock()?.get(hash) {
        None => Err(format!("API with hash {} was not resolved. Could not return address.", hash))?,
        Some(a) => Ok(*a)
    }
}

// Returns the function address for the given API hash, using the provided module
pub fn resolve_api(hash: u32, module_name: &str) -> Result<u64, Box<dyn Error>> {
    println!("Resolving API with hash {:x} from module {}", hash, module_name);

    // Check if we already resolved this API
    if resolved_api(&hash)? {
        #[cfg(debug_assertions)]
        println!("Returning pre-resolved address");
        return Ok(get_hashed_api_addr(&hash)?);
    }

    // Process module and get resolved API address
    match process_module_eat(module_name) {
        Ok(_) => {
            if resolved_api(&hash)? {
                #[cfg(debug_assertions)]
                println!("Returning pre-resolved address");
                Ok(get_hashed_api_addr(&hash)?)
            } else {
                Err(format!("Failed to resolve hash {:x} after processing module {}", hash, module_name))?
            }
        },
        Err(e) => {
            Err(format!("Failed to process module {}: {}", module_name, e))?
        }
    }
}
