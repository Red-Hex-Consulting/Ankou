package main

import (
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client wraps a websocket connection with a mutex for safe concurrent writes
type Client struct {
	conn  *websocket.Conn
	mutex sync.Mutex
}

// WriteJSON safely writes JSON to the websocket connection
func (c *Client) WriteJSON(v interface{}) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.conn.WriteJSON(v)
}

// Close safely closes the websocket connection
func (c *Client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.conn.Close()
}

func broadcastAgents() {
	agents, err := getAllAgents()
	if err != nil {
		log.Printf("Error getting agents for broadcast: %v", err)
		return
	}

	message := map[string]interface{}{
		"type": "agents",
		"data": agents,
	}

	for client := range clients {
		err := client.WriteJSON(message)
		if err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}

func broadcastUsers() {
	users, err := getAllUsers()
	if err != nil {
		log.Printf("Error getting users for broadcast: %v", err)
		return
	}

	message := map[string]interface{}{
		"type": "users",
		"data": users,
	}

	for client := range clients {
		err := client.WriteJSON(message)
		if err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}

func broadcastListeners() {
	allListeners, err := getAllListeners()
	if err != nil {
		log.Printf("Error getting listeners for broadcast: %v", err)
		return
	}

	message := map[string]interface{}{
		"type": "listeners",
		"data": allListeners,
	}

	for client := range clients {
		if err := client.WriteJSON(message); err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}

func broadcastHandlers() {
	allHandlers, err := getAllAgentHandlers()
	if err != nil {
		log.Printf("Error getting agent handlers for broadcast: %v", err)
		return
	}

	message := map[string]interface{}{
		"type": "handlers",
		"data": allHandlers,
	}

	for client := range clients {
		if err := client.WriteJSON(message); err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}

func broadcastLootUpdate(agentID string) {
	files, err := getLootFiles(agentID)
	if err != nil {
		log.Printf("Error getting loot files for broadcast: %v", err)
		return
	}

	message := map[string]interface{}{
		"type":    "loot_response",
		"agentId": agentID,
		"data":    files,
	}

	for client := range clients {
		if err := client.WriteJSON(message); err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}

func handleCommandSubmission(client *Client, msg map[string]interface{}) {
	agentID, ok := msg["agentId"].(string)
	if !ok {
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Invalid agentId",
		})
		return
	}

	command, ok := msg["command"].(string)
	if !ok {
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Invalid command",
		})
		return
	}

	// Get username from message, default to "reaper" for backward compatibility
	username, ok := msg["username"].(string)
	if !ok {
		username = "reaper" // Default for backward compatibility
	}

	// Insert command into database
	now := time.Now()
	result, err := db.Exec("INSERT INTO commands (agent_id, command, client_username, status, created_at) VALUES (?, ?, ?, ?, ?)",
		agentID, command, username, "pending", now)
	if err != nil {
		log.Printf("Error inserting command: %v", err)
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Failed to queue command",
		})
		return
	}

	commandID, _ := result.LastInsertId()

	// Log the command to the logs table
	logCommand(username, agentID, command)

	// Send confirmation
	client.WriteJSON(map[string]interface{}{
		"type":      "command_queued",
		"commandId": commandID,
		"agentId":   agentID,
		"command":   command,
	})

	// Broadcast to all clients that a new command was queued
	broadcastCommandUpdate(agentID)
}

func handleGetCommands(client *Client, msg map[string]interface{}) {
	agentID, ok := msg["agentId"].(string)
	if !ok {
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Invalid agentId",
		})
		return
	}

	commands, err := getCommandsForAgent(agentID)
	if err != nil {
		log.Printf("Error getting commands: %v", err)
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Failed to fetch commands",
		})
		return
	}

	client.WriteJSON(map[string]interface{}{
		"type":    "commands",
		"agentId": agentID,
		"data":    commands,
	})
}

func broadcastCommandUpdate(agentID string) {
	commands, err := getCommandsForAgent(agentID)
	if err != nil {
		log.Printf("Error getting commands for broadcast: %v", err)
		return
	}

	message := map[string]interface{}{
		"type":    "commands_update",
		"agentId": agentID,
		"data":    commands,
	}

	for client := range clients {
		err := client.WriteJSON(message)
		if err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}
