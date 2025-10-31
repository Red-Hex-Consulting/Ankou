package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const agentHandlersDir = "agent_handlers"

type agentHandlerConfig struct {
	ID                string   `json:"id,omitempty"`
	AgentName         string   `json:"agentName"`
	AgentHeaderID     string   `json:"agentHttpHeaderId"`
	SupportedCommands []string `json:"supportedCommands"`
}

func loadAgentHandlersFromConfig() error {
	if err := os.MkdirAll(agentHandlersDir, 0o755); err != nil {
		return err
	}

	entries, err := os.ReadDir(agentHandlersDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(agentHandlersDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Error reading agent handler config %s: %v", entry.Name(), err)
			continue
		}

		var cfg agentHandlerConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Printf("Error parsing agent handler config %s: %v", entry.Name(), err)
			continue
		}

		handler, err := agentHandlerFromConfig(&cfg)
		if err != nil {
			log.Printf("Invalid agent handler config %s: %v", entry.Name(), err)
			continue
		}

	if handler.ID == "" {
		handler.ID = strings.TrimSuffix(entry.Name(), ".json")
	}

	registerAgentHandler(handler)
	}

	log.Printf("Loaded %d agent handlers from config files", len(agentHandlers))
	broadcastHandlers()
	return nil
}

func agentHandlerFromConfig(cfg *agentHandlerConfig) (*AgentHandler, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	name := strings.TrimSpace(cfg.AgentName)
	if name == "" {
		return nil, errors.New("agentName is required")
	}
	headerID := normalizeHandlerHeader(cfg.AgentHeaderID)
	if headerID == "" {
		return nil, errors.New("agentHttpHeaderId is required")
	}

	supported := sanitizeSupportedCommands(cfg.SupportedCommands)

	handler := &AgentHandler{
		ID:                strings.TrimSpace(cfg.ID),
		AgentName:         name,
		AgentHeaderID:     headerID,
		SupportedCommands: supported,
	}

	return handler, nil
}

func sanitizeSupportedCommands(commands []string) []string {
	if len(commands) == 0 {
		return []string{}
	}

	seen := make(map[string]struct{})
	var result []string
	for _, cmd := range commands {
		trimmed := strings.TrimSpace(cmd)
		if trimmed == "" {
			continue
		}
		lowered := strings.ToLower(trimmed)
		if _, exists := seen[lowered]; exists {
			continue
		}
		seen[lowered] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func normalizeHandlerHeader(header string) string {
	return strings.ToLower(strings.TrimSpace(header))
}

func registerAgentHandler(handler *AgentHandler) {
	if handler == nil {
		return
	}

	if handler.ID == "" {
		handler.ID = generateAgentHandlerID()
	}

	agentHandlers[handler.ID] = handler

	// Remove previous header mapping for this handler ID
	for key, existing := range agentHandlersByHeader {
		if existing.ID == handler.ID && key != normalizeHandlerHeader(handler.AgentHeaderID) {
			delete(agentHandlersByHeader, key)
		}
	}

	agentHandlersByHeader[normalizeHandlerHeader(handler.AgentHeaderID)] = handler
}

func saveAgentHandlerConfig(handler *AgentHandler) error {
	if handler == nil {
		return errors.New("handler is nil")
	}

	if handler.ID == "" {
		handler.ID = generateAgentHandlerID()
	}

	cfg := agentHandlerConfig{
		ID:                handler.ID,
		AgentName:         handler.AgentName,
		AgentHeaderID:     handler.AgentHeaderID,
		SupportedCommands: handler.SupportedCommands,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(agentHandlersDir, 0o755); err != nil {
		return err
	}

	path := filepath.Join(agentHandlersDir, fmt.Sprintf("%s.json", handler.ID))
	return os.WriteFile(path, data, 0o644)
}

func deleteAgentHandlerConfig(id string) error {
	if id == "" {
		return errors.New("id is required")
	}

	if handler, ok := agentHandlers[id]; ok {
		delete(agentHandlers, id)
		delete(agentHandlersByHeader, normalizeHandlerHeader(handler.AgentHeaderID))
	}

	path := filepath.Join(agentHandlersDir, fmt.Sprintf("%s.json", id))
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}

func getAllAgentHandlers() ([]*AgentHandler, error) {
	var result []*AgentHandler
	for _, handler := range agentHandlers {
		result = append(result, handler)
	}

	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].AgentName) < strings.ToLower(result[j].AgentName)
	})
	return result, nil
}

func generateAgentHandlerID() string {
	return fmt.Sprintf("handler_%d", time.Now().UnixNano())
}

func getAgentHandlerByHeader(header string) (*AgentHandler, bool) {
	if header == "" {
		return nil, false
	}
	handler, ok := agentHandlersByHeader[normalizeHandlerHeader(header)]
	return handler, ok
}

// translateCommand translates a command using the agent's handler mappings
// If no mapping exists, returns the command as-is (passthrough)
func translateCommand(agentID, command string) string {
	// Get agent's handler
	var handlerName string
	err := db.QueryRow("SELECT handler_name FROM agents WHERE id = ?", agentID).Scan(&handlerName)
	if err != nil {
		// No handler or agent not found, pass through
		return command
	}

	// Get handler
	var handler *AgentHandler
	for _, h := range agentHandlers {
		if h.AgentName == handlerName {
			handler = h
			break
		}
	}

	if handler == nil || handler.CommandMappings == nil {
		// No handler or no mappings, pass through
		return command
	}

	// Parse command to get the first word
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return command
	}

	cmdName := parts[0]

	// Check if mapping exists
	if mappedID, ok := handler.CommandMappings[cmdName]; ok {
		// Replace command name with mapped ID
		parts[0] = mappedID
		return strings.Join(parts, " ")
	}

	// No mapping found, pass through
	return command
}

func upsertAgentHandlerFromJSON(rawConfig string) (*AgentHandler, bool, error) {
	var cfg agentHandlerConfig
	if err := json.Unmarshal([]byte(rawConfig), &cfg); err != nil {
		return nil, false, fmt.Errorf("invalid JSON: %w", err)
	}

	handler, err := agentHandlerFromConfig(&cfg)
	if err != nil {
		return nil, false, err
	}

	created := false
	if existing, ok := agentHandlersByHeader[normalizeHandlerHeader(handler.AgentHeaderID)]; ok {
		handler.ID = existing.ID
	} else if handler.ID != "" {
		if _, ok := agentHandlers[handler.ID]; !ok {
			created = true
		}
	} else {
		created = true
	}

	registerAgentHandler(handler)

	if err := saveAgentHandlerConfig(handler); err != nil {
		return nil, false, err
	}

	return handler, created, nil
}
