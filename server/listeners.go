package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// loadListenersFromConfig loads listener configurations from config files
func loadListenersFromConfig() error {
	// Create listeners directory if it doesn't exist
	if err := os.MkdirAll("listeners", 0755); err != nil {
		return err
	}

	// Read all config files in listeners directory
	files, err := os.ReadDir("listeners")
	if err != nil {
		return err
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			configPath := fmt.Sprintf("listeners/%s", file.Name())
			data, err := os.ReadFile(configPath)
			if err != nil {
				log.Printf("Error reading listener config %s: %v", configPath, err)
				continue
			}

			var listener Listener
			if err := json.Unmarshal(data, &listener); err != nil {
				log.Printf("Error parsing listener config %s: %v", configPath, err)
				continue
			}

			normalizedEndpoint, err := normalizeEndpoint(listener.Endpoint)
			if err != nil {
				log.Printf("Invalid endpoint in listener config %s: %v", configPath, err)
				continue
			}

			listener.Endpoint = normalizedEndpoint

			// Always start listeners in stopped state on server boot
			if strings.ToLower(listener.Status) == "running" {
				listener.Status = "stopped"
			}

			listenerCopy := listener
			listeners[listener.ID] = &listenerCopy
		}
	}

	log.Printf("Loaded %d listeners from config files", len(listeners))
	return nil
}

// saveListenerConfig saves a listener configuration to a file
func saveListenerConfig(listener *Listener) error {
	// Create listeners directory if it doesn't exist
	if err := os.MkdirAll("listeners", 0755); err != nil {
		return err
	}

	normalizedEndpoint, err := normalizeEndpoint(listener.Endpoint)
	if err != nil {
		return err
	}
	listener.Endpoint = normalizedEndpoint

	configPath := fmt.Sprintf("listeners/%s.json", listener.ID)
	data, err := json.MarshalIndent(listener, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// deleteListenerConfig deletes a listener configuration file
func deleteListenerConfig(listenerID string) error {
	configPath := fmt.Sprintf("listeners/%s.json", listenerID)
	return os.Remove(configPath)
}

// getAllListeners returns all listeners
func getAllListeners() ([]*Listener, error) {
	var result []*Listener
	for _, listener := range listeners {
		result = append(result, listener)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

// validListenerTypes defines the allowed listener types
var validListenerTypes = map[string]bool{
	"ghost_relay": true,
	"phantasm":    true,
	"shade":       true,
	"geist":       true,
	"anomaly":     true,
	"wraith":      true,
}

// createListener creates a new listener
func createListener(name, listenerType string, port int, endpoint, description string) (*Listener, error) {
	if listenerType == "" {
		listenerType = "ghost_relay"
	}
	if !validListenerTypes[listenerType] {
		return nil, fmt.Errorf("invalid listener type: %s", listenerType)
	}

	// Agent-specific listeners require a port
	if listenerType != "ghost_relay" && port <= 0 {
		return nil, fmt.Errorf("port is required for %s listeners", listenerType)
	}

	// Generate unique ID
	listenerID := fmt.Sprintf("listener_%d", time.Now().Unix())

	normalizedEndpoint, err := normalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	listener := &Listener{
		ID:          listenerID,
		Name:        name,
		Type:        listenerType,
		Port:        port,
		Endpoint:    normalizedEndpoint,
		Status:      "stopped",
		Description: description,
		CreatedAt:   time.Now(),
	}

	// Save to memory
	listeners[listenerID] = listener

	// Save to config file
	if err := saveListenerConfig(listener); err != nil {
		delete(listeners, listenerID)
		return nil, err
	}

	return listener, nil
}

// startListener starts a listener
func startListener(id string) (*Listener, error) {
	listener, exists := listeners[id]
	if !exists {
		return nil, fmt.Errorf("listener not found")
	}

	if listener.Status == "running" {
		return listener, nil // Already running
	}

	// For agent-specific listeners, start an actual HTTPS server
	if listener.Type != "ghost_relay" {
		if err := startAgentListenerServer(listener); err != nil {
			return nil, fmt.Errorf("failed to start listener server: %v", err)
		}
	}

	listener.Status = "running"
	log.Printf("Activated listener: %s (type: %s, port: %d, endpoint: %s)", listener.Name, listener.Type, listener.Port, listener.Endpoint)

	// Save updated status
	if err := saveListenerConfig(listener); err != nil {
		log.Printf("Error saving listener config: %v", err)
	}

	return listener, nil
}

// stopListener stops a listener
func stopListener(id string) (*Listener, error) {
	listener, exists := listeners[id]
	if !exists {
		return nil, fmt.Errorf("listener not found")
	}

	if listener.Status == "stopped" {
		return listener, nil // Already stopped
	}

	// For agent-specific listeners, stop the actual server
	if listener.Type != "ghost_relay" {
		stopAgentListenerServer(listener.ID)
	}

	listener.Status = "stopped"
	log.Printf("Deactivated listener: %s (type: %s)", listener.Name, listener.Type)

	// Save updated status
	if err := saveListenerConfig(listener); err != nil {
		log.Printf("Error saving listener config: %v", err)
	}

	return listener, nil
}

// deleteListener deletes a listener
func deleteListener(id string) (bool, error) {
	listener, exists := listeners[id]
	if !exists {
		return false, fmt.Errorf("listener not found")
	}

	// Stop the listener if it's running
	if listener.Status == "running" {
		if listener.Type != "ghost_relay" {
			stopAgentListenerServer(listener.ID)
		}
		listener.Status = "stopped"
		log.Printf("Deactivated listener: %s (type: %s)", listener.Name, listener.Type)
	}

	// Remove from memory
	delete(listeners, id)

	// Delete config file
	if err := deleteListenerConfig(id); err != nil {
		log.Printf("Error deleting listener config: %v", err)
	}

	return true, nil
}

// isListenerActive checks if a ghost_relay listener is running for the given endpoint
func isListenerActive(endpoint string) bool {
	listenersMutex.RLock()
	defer listenersMutex.RUnlock()
	
	for _, listener := range listeners {
		if listener.Endpoint == endpoint && listener.Status == "running" {
			return true
		}
	}
	return false
}

func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)

	if endpoint == "" {
		return "/", nil
	}

	if strings.ContainsAny(endpoint, " \t\n\r") {
		return "", fmt.Errorf("endpoint cannot contain whitespace")
	}

	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	cleaned := path.Clean(endpoint)
	if cleaned == "." {
		cleaned = "/"
	}

	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned, nil
}

// listenerProtocol returns the protocol for a given listener type
func listenerProtocol(listenerType string) string {
	switch listenerType {
	case "phantasm", "anomaly":
		return "https"
	case "geist", "wraith":
		return "quic"
	case "shade":
		return "ssh"
	default:
		return ""
	}
}
