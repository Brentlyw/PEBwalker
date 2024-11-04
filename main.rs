use std::ffi::c_void;
use std::ptr::null_mut;
use winapi::shared::ntdef::NTSTATUS;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};

// Mem alloc callback sig
type MemAllocRoutine = unsafe extern "system" fn(
    proc: *mut c_void,
    addr: *mut *mut c_void,
    zero: u32,
    size: *mut usize,
    alloc_type: u32,
    protect: u32,
) -> NTSTATUS;

//Calculate hash for api
fn calc_checksum(input: &[u8]) -> u32 {
    //Base offset for hash (seed prime)
    let mut sum = 0x811c9dc5u32;
    for b in input {
        let upper = b.to_ascii_uppercase();
        sum ^= upper as u32;
        //Prime multiplier for distrib
        sum = sum.wrapping_mul(0x01000193);
    }
    sum
}

//Handle widechar strings from sys tables
fn calc_wide_checksum(wide_str: &[u16]) -> u32 {
    let mut sum = 0x811c9dc5u32;
    for &c in wide_str {
        //Split widechar into bytes
        let bytes = [
            (c & 0xFF) as u8,
            ((c >> 8) & 0xFF) as u8
        ];
        
        //Hash each byte after
        for b in bytes.iter() {
            let upper = b.to_ascii_uppercase();
            sum ^= upper as u32;
            sum = sum.wrapping_mul(0x01000193);
        }
    }
    sum
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TableEntry {
    next: *mut TableEntry,
    prev: *mut TableEntry,  
}

#[repr(C)]
#[derive(Copy, Clone)]
struct WideString {
    len: u16,
    max_len: u16,
    ptr: *mut u16,
}

// Get proc enviro pntr 
fn get_env_block() -> *mut c_void {
    unsafe {
        let env: *mut c_void;
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) env,
            );
        }
        #[cfg(target_arch = "x86")]
        {
            std::arch::asm!(
                "mov {}, fs:[0x30]",
                out(reg) env,
            );
        }
        env
    }
}

fn find_routine(lib_sum: u32, func_sum: u32) -> *mut c_void {
    unsafe {
        let env = get_env_block();
        println!("Environment at: {:?}", env);
        
        let loader = *(env.add(0x18) as *mut *mut c_void);
        println!("Loader at: {:?}", loader);
        
        let mods = loader.add(0x20) as *mut TableEntry;
        let first = (*mods).next;
        let mut current = first;

        println!("Scanning loaded modules");
        
        loop {
            let entry = (current as usize - 0x10) as *mut c_void;
            let base = *(entry.add(0x30) as *mut *mut c_void);
            let name = *(entry.add(0x58) as *mut WideString);
            
            let name_slice = std::slice::from_raw_parts(
                name.ptr,
                name.len as usize / 2
            );
            
            let mod_name = String::from_utf16_lossy(name_slice);
            let mod_sum = calc_wide_checksum(name_slice);
            
            println!("Found module: {}, sum: {:#x}", mod_name, mod_sum);

            if mod_sum == lib_sum {
                println!("Located target module: {}", mod_name);
                
                let dos = base as *const IMAGE_DOS_HEADER;
                let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
                let exports = (base as usize + (*nt).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
                    as *const IMAGE_EXPORT_DIRECTORY;

                let funcs = (base as usize + (*exports).AddressOfFunctions as usize) as *const u32;
                let names = (base as usize + (*exports).AddressOfNames as usize) as *const u32;
                let ords = (base as usize + (*exports).AddressOfNameOrdinals as usize) as *const u16;

                println!("Processing {} exports...", (*exports).NumberOfNames);

                for i in 0..(*exports).NumberOfNames {
                    let name_rva = *names.add(i as usize);
                    let func_name = (base as usize + name_rva as usize) as *const u8;
                    
                    let mut len = 0;
                    while *func_name.add(len) != 0 {
                        len += 1;
                    }
                    
                    let name_bytes = std::slice::from_raw_parts(func_name, len);
                    let func_sum = calc_checksum(name_bytes);
                    let name_str = std::str::from_utf8_unchecked(name_bytes);
                    println!("Export: {}, sum: {:#x}", name_str, func_sum);

                    if func_sum == func_sum {
                        println!("Found target routine: {}", name_str);
                        let ord = *ords.add(i as usize);
                        let rva = *funcs.add(ord as usize);
                        return (base as usize + rva as usize) as *mut c_void;
                    }
                }
            }

            current = (*current).next;
            if current == first {
                break;
            }
        }
        
        println!("Target routine not found");
        null_mut()
    }
}

fn main() {
    let target_lib: Vec<u16> = "ntdll.dll".encode_utf16().collect();
    let lib_sum = calc_wide_checksum(&target_lib);
    
    let target_func = calc_checksum(b"NtAllocateVirtualMemory");

    println!("Module checksum: {:#x}", lib_sum);
    println!("Routine checksum: {:#x}", target_func);

    let routine_ptr = find_routine(lib_sum, target_func);

    if routine_ptr.is_null() {
        println!("Failed to locate routine ):");
    } else {
        println!("Routine located at: {:?}", routine_ptr);
        
        let _routine: MemAllocRoutine = unsafe { std::mem::transmute(routine_ptr) };
    }
}