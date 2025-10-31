package main

import (
	"log"
	"time"
)

// handleGlobalCommand handles commands that should be sent to all agents
func handleGlobalCommand(client *Client, msg map[string]interface{}) {
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

	// Get all agents
	agents, err := getAllAgents()
	if err != nil {
		log.Printf("Error getting agents for global command: %v", err)
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Failed to get agents",
		})
		return
	}

	if len(agents) == 0 {
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "No agents available",
		})
		return
	}

	// Queue command for each agent (regardless of status)
	var queuedAgents []string
	now := time.Now()

	for _, agent := range agents {
		// Translate command using handler mappings (if available)
		translatedCommand := translateCommand(agent.ID, command)

		result, err := db.Exec("INSERT INTO commands (agent_id, command, client_username, status, created_at) VALUES (?, ?, ?, ?, ?)",
			agent.ID, translatedCommand, username, "pending", now)
		if err != nil {
			log.Printf("Error inserting global command for agent %s: %v", agent.ID, err)
			continue
		}

		commandID, _ := result.LastInsertId()

		// Log the command to the logs table
		logCommand(username, agent.ID, command)

		// Broadcast command update for this agent
		broadcastCommandUpdate(agent.ID)

		queuedAgents = append(queuedAgents, agent.ID)

		log.Printf("Global command queued for agent %s (ID: %d): %s", agent.ID, commandID, command)
	}

	// Send confirmation
	client.WriteJSON(map[string]interface{}{
		"type":       "global_command_queued",
		"command":    command,
		"agentCount": len(queuedAgents),
		"agents":     queuedAgents,
	})

	log.Printf("Global command '%s' queued for %d agents", command, len(queuedAgents))
}

// getGlobalCommands returns all commands that were sent globally (same command text across multiple agents)
func getGlobalCommands() ([]map[string]interface{}, error) {
	query := `
		SELECT 
			c.command,
			c.client_username,
			c.created_at,
			COUNT(*) as agent_count,
			GROUP_CONCAT(c.agent_id) as agent_ids,
			GROUP_CONCAT(c.status) as statuses
		FROM commands c
		WHERE c.created_at >= datetime('now', '-24 hours')
		GROUP BY c.command, c.client_username, c.created_at
		HAVING COUNT(*) > 1
		ORDER BY c.created_at DESC
		LIMIT 50
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var globalCommands []map[string]interface{}
	for rows.Next() {
		var command, clientUsername, createdAt, agentIDs, statuses string
		var agentCount int

		err := rows.Scan(&command, &clientUsername, &createdAt, &agentCount, &agentIDs, &statuses)
		if err != nil {
			return nil, err
		}

		globalCommands = append(globalCommands, map[string]interface{}{
			"command":        command,
			"clientUsername": clientUsername,
			"createdAt":      createdAt,
			"agentCount":     agentCount,
			"agentIds":       agentIDs,
			"statuses":       statuses,
		})
	}

	return globalCommands, nil
}
