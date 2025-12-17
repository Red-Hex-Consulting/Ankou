//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func getPrivilegeInfo() string {
	// Windows privilege detection
	isElevated := isElevated()
	isAdmin := isAdminGroup()

	// Marshal to JSON manually to avoid import
	return `{"isRoot":` + boolToString(isElevated) + `,"isAdmin":` + boolToString(isAdmin) + `}`
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// isElevated checks if the process is running with elevated privileges
func isElevated() bool {
	// Load advapi32.dll
	advapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return false
	}
	defer advapi32.Release()

	// Get process token
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return false
	}
	defer kernel32.Release()

	getCurrentProcess, err := kernel32.FindProc("GetCurrentProcess")
	if err != nil {
		return false
	}

	openProcessToken, err := advapi32.FindProc("OpenProcessToken")
	if err != nil {
		return false
	}

	getTokenInformation, err := advapi32.FindProc("GetTokenInformation")
	if err != nil {
		return false
	}

	closeHandle, err := kernel32.FindProc("CloseHandle")
	if err != nil {
		return false
	}

	// Get current process handle
	currentProcess, _, _ := getCurrentProcess.Call()

	// Open process token
	const TOKEN_QUERY = 0x0008
	var token uintptr
	ret, _, _ := openProcessToken.Call(
		currentProcess,
		TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return false
	}
	defer closeHandle.Call(token)

	// Query token elevation
	const TokenElevation = 20
	var elevation uint32
	var returnLength uint32
	ret, _, _ = getTokenInformation.Call(
		token,
		TokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 {
		return false
	}

	return elevation != 0
}

// isAdminGroup checks if the user is a member of the Administrators group
func isAdminGroup() bool {
	// Load advapi32.dll
	advapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return false
	}
	defer advapi32.Release()

	allocateAndInitializeSid, err := advapi32.FindProc("AllocateAndInitializeSid")
	if err != nil {
		return false
	}

	checkTokenMembership, err := advapi32.FindProc("CheckTokenMembership")
	if err != nil {
		return false
	}

	freeSid, err := advapi32.FindProc("FreeSid")
	if err != nil {
		return false
	}

	// SECURITY_NT_AUTHORITY
	var sidAuth = [6]byte{0, 0, 0, 0, 0, 5}
	var adminGroup uintptr

	// SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
	// DOMAIN_ALIAS_RID_ADMINS = 0x00000220
	ret, _, _ := allocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&sidAuth)),
		2,          // SubAuthorityCount
		0x00000020, // SECURITY_BUILTIN_DOMAIN_RID
		0x00000220, // DOMAIN_ALIAS_RID_ADMINS
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&adminGroup)),
	)
	if ret == 0 {
		return false
	}
	defer freeSid.Call(adminGroup)

	// Check if current user is member of admin group
	var isMember int32
	ret, _, _ = checkTokenMembership.Call(
		0, // NULL token (use current thread token)
		adminGroup,
		uintptr(unsafe.Pointer(&isMember)),
	)
	if ret == 0 {
		return false
	}

	return isMember != 0
}
