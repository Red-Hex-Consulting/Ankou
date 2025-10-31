import { useState, useEffect, useMemo } from "react";
import { FaFileCode, FaPlus, FaUpload, FaTrash, FaEdit, FaSearch } from "react-icons/fa";
import DeleteScriptModal from "./DeleteScriptModal";
import "./Scripts.css";

interface ScriptsProps {
  isActive: boolean;
}

interface Script {
  id: string;
  name: string;
  commands: string[];
  createdAt: string;
}

const SCRIPTS_STORAGE_KEY = "ankou_scripts";

export default function Scripts({ isActive }: ScriptsProps) {
  const [scripts, setScripts] = useState<Script[]>([]);
  const [editingScript, setEditingScript] = useState<Script | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [scriptName, setScriptName] = useState("");
  const [scriptContent, setScriptContent] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [deleteModal, setDeleteModal] = useState<{ visible: boolean; script: Script | null }>({
    visible: false,
    script: null,
  });

  // Load scripts from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem(SCRIPTS_STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setScripts(Array.isArray(parsed) ? parsed : []);
      } catch {
        setScripts([]);
      }
    }
  }, []);

  // Save scripts to localStorage whenever they change
  useEffect(() => {
    localStorage.setItem(SCRIPTS_STORAGE_KEY, JSON.stringify(scripts));
  }, [scripts]);

  const handleCreateScript = () => {
    if (!scriptName.trim() || !scriptContent.trim()) {
      alert("Please provide both a name and commands for the script");
      return;
    }

    const commands = scriptContent
      .split("\n")
      .map((cmd) => cmd.trim())
      .filter((cmd) => cmd.length > 0);

    if (commands.length === 0) {
      alert("Script must contain at least one command");
      return;
    }

    const newScript: Script = {
      id: Date.now().toString(),
      name: scriptName.trim(),
      commands,
      createdAt: new Date().toISOString(),
    };

    setScripts([...scripts, newScript]);
    setScriptName("");
    setScriptContent("");
    setIsCreating(false);
  };

  const handleUpdateScript = () => {
    if (!editingScript || !scriptName.trim() || !scriptContent.trim()) {
      alert("Please provide both a name and commands for the script");
      return;
    }

    const commands = scriptContent
      .split("\n")
      .map((cmd) => cmd.trim())
      .filter((cmd) => cmd.length > 0);

    if (commands.length === 0) {
      alert("Script must contain at least one command");
      return;
    }

    setScripts(
      scripts.map((s) =>
        s.id === editingScript.id
          ? { ...s, name: scriptName.trim(), commands }
          : s
      )
    );
    setEditingScript(null);
    setScriptName("");
    setScriptContent("");
  };

  const handleDeleteScript = (script: Script) => {
    setDeleteModal({ visible: true, script });
  };

  const confirmDeleteScript = () => {
    if (deleteModal.script) {
      setScripts(scripts.filter((s) => s.id !== deleteModal.script!.id));
    }
    setDeleteModal({ visible: false, script: null });
  };

  const cancelDeleteScript = () => {
    setDeleteModal({ visible: false, script: null });
  };

  const handleEditScript = (script: Script) => {
    setEditingScript(script);
    setScriptName(script.name);
    setScriptContent(script.commands.join("\n"));
    setIsCreating(false);
  };

  const handleCancelEdit = () => {
    setEditingScript(null);
    setScriptName("");
    setScriptContent("");
    setIsCreating(false);
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (content) {
        setScriptContent(content);
        if (!scriptName) {
          setScriptName(file.name.replace(/\.[^/.]+$/, ""));
        }
      }
    };
    reader.readAsText(file);
    
    // Clear the input so the same file can be selected again
    event.target.value = "";
  };

  const handleNewScript = () => {
    setIsCreating(true);
    setEditingScript(null);
    setScriptName("");
    setScriptContent("");
  };

  // Filter scripts based on search query
  const filteredScripts = useMemo(() => {
    if (!searchQuery.trim()) return scripts;
    const query = searchQuery.toLowerCase();
    return scripts.filter((script) =>
      script.name.toLowerCase().includes(query)
    );
  }, [scripts, searchQuery]);

  if (!isActive) return null;

  return (
    <div className="scripts-container">
      {/* Header Bar */}
      <div className="scripts-search">
        <div className="scripts-stats">
          <FaFileCode className="stats-icon" />
          <span className="stats-text">{scripts.length} Script{scripts.length !== 1 ? "s" : ""}</span>
        </div>
        <div className="scripts-search-input-wrapper">
          <FaSearch className="search-icon" />
          <input
            type="text"
            className="scripts-search-input"
            placeholder="Search scripts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <button
          className="scripts-add-btn"
          onClick={handleNewScript}
          disabled={isCreating || !!editingScript}
        >
          <FaPlus /> New Script
        </button>
      </div>

      {/* Content Area */}
      <div className="scripts-content">
        {/* Create/Edit Form */}
        {(isCreating || editingScript) && (
          <div className="scripts-form-container">
            <div className="script-editor">
              <h3>{editingScript ? "Edit Script" : "New Script"}</h3>
              
              <div className="script-form-row">
                <input
                  type="text"
                  placeholder="Script Name *"
                  value={scriptName}
                  onChange={(e) => setScriptName(e.target.value)}
                />
              </div>

              <div className="script-form-row">
                <textarea
                  placeholder="Commands (one per line) *"
                  value={scriptContent}
                  onChange={(e) => setScriptContent(e.target.value)}
                />
              </div>
              <div className="script-hint">
                Enter each command on a new line. Commands will be executed in order.
              </div>

              <div className="script-form-actions">
                <label className="scripts-upload-label">
                  <FaUpload />
                  Upload Script
                  <input
                    type="file"
                    accept=".txt,.sh,.ps1,.bat,.script"
                    onChange={handleFileUpload}
                  />
                </label>
                <button
                  className="scripts-save-btn"
                  onClick={editingScript ? handleUpdateScript : handleCreateScript}
                >
                  {editingScript ? "Update" : "Save"}
                </button>
                <button
                  className="scripts-cancel-btn"
                  onClick={handleCancelEdit}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Scripts List */}
        {scripts.length === 0 && !isCreating && !editingScript ? (
          <div className="scripts-empty">
            <FaFileCode className="empty-icon" />
            <p>No scripts created yet</p>
          </div>
        ) : !isCreating && !editingScript && (
          <div className="scripts-list">
            {filteredScripts.length === 0 ? (
              <div className="scripts-empty">
                <FaFileCode className="empty-icon" />
                <p>No scripts match your search</p>
              </div>
            ) : (
              filteredScripts.map((script) => (
                <div key={script.id} className="script-item">
                  <div className="script-item-header">
                    <div className="script-item-info">
                      <FaFileCode className="script-item-icon" />
                      <div>
                        <h4>{script.name}</h4>
                        <span className="script-item-meta">
                          {script.commands.length} command{script.commands.length !== 1 ? "s" : ""} • 
                          {" "}{new Date(script.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                    <div className="script-item-actions">
                      <button
                        className="edit-button"
                        onClick={() => handleEditScript(script)}
                        title="Edit script"
                      >
                        <FaEdit />
                      </button>
                      <button
                        className="delete-button"
                        onClick={() => handleDeleteScript(script)}
                        title="Delete script"
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </div>
                <div className="script-item-preview">
                  {script.commands.slice(0, 3).map((cmd, idx) => (
                    <div key={idx} className="command-line">
                      <span className="command-prompt">$</span>
                      <code>{cmd}</code>
                    </div>
                  ))}
                  {script.commands.length > 3 && (
                    <div className="command-line more">
                      <span className="command-prompt">...</span>
                      <span>and {script.commands.length - 3} more</span>
                    </div>
                  )}
                </div>
              </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      <DeleteScriptModal
        isVisible={deleteModal.visible}
        scriptName={deleteModal.script?.name || ""}
        onConfirm={confirmDeleteScript}
        onCancel={cancelDeleteScript}
      />
    </div>
  );
}

// Export scripts getter for use in other components
export function getScripts(): Script[] {
  const saved = localStorage.getItem(SCRIPTS_STORAGE_KEY);
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

