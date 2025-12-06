package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

func createUsersTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(query)
	return err
}

func createLogsTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS logs (
		id TEXT PRIMARY KEY,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		level TEXT NOT NULL,
		message TEXT NOT NULL,
		source TEXT NOT NULL
	)`

	_, err := db.Exec(query)
	return err
}

func getAllAgents() ([]Agent, error) {
	rows, err := db.Query("SELECT id, name, status, ip, last_seen, os, created_at, handler_id, handler_name, reconnect_interval FROM agents WHERE is_removed = 0 OR is_removed IS NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var agent Agent
		var handlerID sql.NullString
		var handlerName sql.NullString
		err := rows.Scan(&agent.ID, &agent.Name, &agent.Status, &agent.IP, &agent.LastSeen, &agent.OS, &agent.CreatedAt, &handlerID, &handlerName, &agent.ReconnectInterval)
		if err != nil {
			return nil, err
		}
		if handlerID.Valid {
			agent.HandlerID = handlerID.String
		}
		if handlerName.Valid {
			agent.HandlerName = handlerName.String
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

func removeAgent(agentID string) error {
	_, err := db.Exec("UPDATE agents SET is_removed = 1 WHERE id = ?", agentID)
	return err
}

func getAgentByID(agentID string) (*Agent, error) {
	row := db.QueryRow("SELECT id, name, status, ip, last_seen, os, created_at, handler_id, handler_name, reconnect_interval FROM agents WHERE id = ?", agentID)

	var agent Agent
	var handlerID sql.NullString
	var handlerName sql.NullString
	err := row.Scan(&agent.ID, &agent.Name, &agent.Status, &agent.IP, &agent.LastSeen, &agent.OS, &agent.CreatedAt, &handlerID, &handlerName, &agent.ReconnectInterval)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if handlerID.Valid {
		agent.HandlerID = handlerID.String
	}
	if handlerName.Valid {
		agent.HandlerName = handlerName.String
	}

	return &agent, nil
}

func getAllUsers() ([]User, error) {
	rows, err := db.Query("SELECT id, username, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var createdAtStr sql.NullString
		err := rows.Scan(&user.ID, &user.Username, &createdAtStr)
		if err != nil {
			return nil, err
		}

		// Handle null created_at values
		if createdAtStr.Valid {
			// Try multiple timestamp formats
			parsed, err := time.Parse(time.RFC3339Nano, createdAtStr.String)
			if err != nil {
				parsed, err = time.Parse(time.RFC3339, createdAtStr.String)
				if err != nil {
					parsed, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAtStr.String)
					if err != nil {
						parsed, err = time.Parse("2006-01-02 15:04:05", createdAtStr.String)
						if err != nil {
							log.Printf("Error parsing created_at for user %s: %v", user.Username, err)
							parsed = time.Now()
						}
					}
				}
			}
			user.CreatedAt = parsed
		} else {
			user.CreatedAt = time.Now() // Default to current time if null
		}

		users = append(users, user)
	}
	return users, nil
}

func getLogs(limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT id, timestamp, level, message, source 
		FROM logs 
		ORDER BY timestamp DESC 
		LIMIT ?
	`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id, timestamp, level, message, source string
		err := rows.Scan(&id, &timestamp, &level, &message, &source)
		if err != nil {
			return nil, err
		}

		logs = append(logs, map[string]interface{}{
			"id":        id,
			"timestamp": timestamp,
			"level":     level,
			"message":   message,
			"source":    source,
		})
	}

	return logs, nil
}

// getLogsPaginated returns logs with pagination support
func getLogsPaginated(limit, offset int) ([]map[string]interface{}, error) {
	query := `
		SELECT id, timestamp, level, message, source 
		FROM logs 
		ORDER BY timestamp DESC 
		LIMIT ? OFFSET ?
	`

	rows, err := db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id, timestamp, level, message, source string
		err := rows.Scan(&id, &timestamp, &level, &message, &source)
		if err != nil {
			return nil, err
		}

		logs = append(logs, map[string]interface{}{
			"id":        id,
			"timestamp": timestamp,
			"level":     level,
			"message":   message,
			"source":    source,
		})
	}

	return logs, nil
}

// searchLogs returns all logs matching the search term (no pagination)
func searchLogs(search string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, timestamp, level, message, source 
		FROM logs 
		WHERE message LIKE ? OR source LIKE ? OR level LIKE ?
		ORDER BY timestamp DESC
	`

	searchPattern := "%" + search + "%"
	rows, err := db.Query(query, searchPattern, searchPattern, searchPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id, timestamp, level, message, source string
		err := rows.Scan(&id, &timestamp, &level, &message, &source)
		if err != nil {
			return nil, err
		}

		logs = append(logs, map[string]interface{}{
			"id":        id,
			"timestamp": timestamp,
			"level":     level,
			"message":   message,
			"source":    source,
		})
	}

	return logs, nil
}

// getLogsCount returns the total count of logs
func getLogsCount() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM logs").Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// getLogsCountSearch returns the count of logs matching the search term
func getLogsCountSearch(search string) (int, error) {
	var count int
	searchPattern := "%" + search + "%"
	err := db.QueryRow(
		"SELECT COUNT(*) FROM logs WHERE message LIKE ? OR source LIKE ? OR level LIKE ?",
		searchPattern, searchPattern, searchPattern,
	).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func getCommandsForAgent(agentID string) ([]Command, error) {
	rows, err := db.Query("SELECT id, agent_id, command, client_username, status, output, created_at, executed_at FROM commands WHERE agent_id = ? ORDER BY created_at ASC", agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var commands []Command
	for rows.Next() {
		var cmd Command
		var executedAt sql.NullTime
		var output sql.NullString
		err := rows.Scan(&cmd.ID, &cmd.AgentID, &cmd.Command, &cmd.ClientUsername, &cmd.Status, &output, &cmd.CreatedAt, &executedAt)
		if err != nil {
			return nil, err
		}
		if output.Valid {
			cmd.Output = output.String
		}
		if executedAt.Valid {
			cmd.ExecutedAt = &executedAt.Time
		}
		commands = append(commands, cmd)
	}
	return commands, nil
}

// getCommandsForAgentPaginated returns commands with pagination (newest first for display, then reversed)
func getCommandsForAgentPaginated(agentID string, limit, offset int) ([]Command, error) {
	// Query orders by created_at DESC to get newest first, with limit and offset
	query := `
		SELECT id, agent_id, command, client_username, status, output, created_at, executed_at 
		FROM commands 
		WHERE agent_id = ? 
		ORDER BY created_at DESC 
		LIMIT ? OFFSET ?
	`

	rows, err := db.Query(query, agentID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var commands []Command
	for rows.Next() {
		var cmd Command
		var executedAt sql.NullTime
		var output sql.NullString
		err := rows.Scan(&cmd.ID, &cmd.AgentID, &cmd.Command, &cmd.ClientUsername, &cmd.Status, &output, &cmd.CreatedAt, &executedAt)
		if err != nil {
			return nil, err
		}
		if output.Valid {
			cmd.Output = output.String
		}
		if executedAt.Valid {
			cmd.ExecutedAt = &executedAt.Time
		}
		commands = append(commands, cmd)
	}

	// Reverse the array to get chronological order (oldest to newest)
	for i, j := 0, len(commands)-1; i < j; i, j = i+1, j-1 {
		commands[i], commands[j] = commands[j], commands[i]
	}

	return commands, nil
}

// getCommandCountForAgent returns the total count of commands for an agent
func getCommandCountForAgent(agentID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM commands WHERE agent_id = ?", agentID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func markOfflineAgents() {
	// Get all agents with their beacon intervals
	rows, err := db.Query("SELECT id, last_seen, reconnect_interval FROM agents")
	if err != nil {
		log.Printf("Error querying agents for status update: %v", err)
		return
	}
	defer rows.Close()

	now := time.Now()

	for rows.Next() {
		var agentID string
		var lastSeenStr string
		var reconnectInterval int

		if err := rows.Scan(&agentID, &lastSeenStr, &reconnectInterval); err != nil {
			log.Printf("Error scanning agent row: %v", err)
			continue
		}

		// Parse last_seen timestamp (try multiple formats)
		var lastSeen time.Time
		var err error

		// Try RFC3339Nano first (ISO 8601 with T)
		lastSeen, err = time.Parse(time.RFC3339Nano, lastSeenStr)
		if err != nil {
			// Try RFC3339
			lastSeen, err = time.Parse(time.RFC3339, lastSeenStr)
			if err != nil {
				// Try with space instead of T
				lastSeen, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", lastSeenStr)
				if err != nil {
					// Try simple format
					lastSeen, err = time.Parse("2006-01-02 15:04:05", lastSeenStr)
					if err != nil {
						log.Printf("Error parsing last_seen for agent %s: %v", agentID, err)
						continue
					}
				}
			}
		}

		// Determine status based on beacon interval
		var newStatus string

		if reconnectInterval == 0 {
			// Unknown interval - always keep as "online" (never mark late)
			newStatus = "online"
		} else {
			// Calculate expected check-in time with jitter buffer (50% grace period)
			jitterBuffer := float64(reconnectInterval) * 0.5
			expectedCheckIn := lastSeen.Add(time.Duration(float64(reconnectInterval)+jitterBuffer) * time.Second)

			if now.After(expectedCheckIn) {
				// Agent is late
				newStatus = "late"
			} else {
				// Agent is on time
				newStatus = "online"
			}
		}

		// Update agent status if changed (with retry logic for SQLITE_BUSY)
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			_, err = db.Exec("UPDATE agents SET status = ? WHERE id = ?", newStatus, agentID)
			if err == nil {
				break
			}

			// If database is locked, retry with exponential backoff
			if strings.Contains(err.Error(), "SQLITE_BUSY") || strings.Contains(err.Error(), "database is locked") {
				if i < maxRetries-1 {
					time.Sleep(time.Duration(50*(i+1)) * time.Millisecond)
					continue
				}
			}

			log.Printf("Error updating agent %s status: %v", agentID, err)
			break
		}
	}
}

func logCommand(username, agentID, command string) {
	id := fmt.Sprintf("log_%d", time.Now().UnixNano())
	message := fmt.Sprintf("[%s] %s: %s", username, agentID, command)

	_, err := db.Exec(`
		INSERT INTO logs (id, level, message, source) 
		VALUES (?, ?, ?, ?)
	`, id, "info", message, "command")

	if err != nil {
		log.Printf("Failed to log command: %v", err)
	}
}

func logCommandResponse(commandID int, output, status string) {
	id := fmt.Sprintf("log_%d", time.Now().UnixNano())
	level := "info"
	if status == "error" {
		level = "error"
	}

	// Truncate long outputs for readability
	truncatedOutput := output
	if len(output) > 200 {
		truncatedOutput = output[:200] + "..."
	}

	message := fmt.Sprintf("Response (ID: %d): %s", commandID, truncatedOutput)

	_, err := db.Exec(`
		INSERT INTO logs (id, level, message, source) 
		VALUES (?, ?, ?, ?)
	`, id, level, message, "response")

	if err != nil {
		log.Printf("Failed to log command response: %v", err)
	}
}
