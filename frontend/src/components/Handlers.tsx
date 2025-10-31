import React, { useMemo, useState } from "react";
import { FaPlus, FaTrash, FaProjectDiagram, FaFileUpload } from "react-icons/fa";
import { useWebSocket, AgentHandler } from "../hooks/useWebSocket";
import DeleteHandlerModal from "./DeleteHandlerModal";
import "./Listeners.css";
import "./Handlers.css";

const escapeGraphQLString = (value: string) =>
  value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "")
    .replace(/\n/g, "\\n");

const validateHandlerConfig = (raw: string) => {
  const parsed = JSON.parse(raw);
  if (!parsed.agentName || typeof parsed.agentName !== "string") {
    throw new Error("agentName must be a non-empty string");
  }
  if (!parsed.agentHttpHeaderId || typeof parsed.agentHttpHeaderId !== "string") {
    throw new Error("agentHttpHeaderId must be a non-empty string");
  }
  if (!Array.isArray(parsed.supportedCommands)) {
    throw new Error("supportedCommands must be an array of strings");
  }
  return parsed as {
    agentName: string;
    agentHttpHeaderId: string;
    supportedCommands: string[];
  };
};

const Handlers: React.FC = () => {
  const { handlers, sendGraphQLQuery } = useWebSocket(true);
  const handlerList = handlers ?? [];
  const [showAddForm, setShowAddForm] = useState(false);
  const [jsonInput, setJsonInput] = useState("");
  const [formError, setFormError] = useState("");
  const [globalError, setGlobalError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});
  const [fileName, setFileName] = useState("");
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [handlerToDelete, setHandlerToDelete] = useState<AgentHandler | null>(null);

  const totalCommands = useMemo(
    () => handlerList.reduce((sum, handler) => sum + (handler.supportedCommands?.length ?? 0), 0),
    [handlerList]
  );

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === "string" ? reader.result : "";
      setJsonInput(text);
      setFileName(file.name);
      setFormError("");
    };
    reader.onerror = () => {
      setFormError("Failed to read file");
    };
    reader.readAsText(file);
  };

  const resetForm = () => {
    setJsonInput("");
    setFileName("");
    setFormError("");
    setGlobalError("");
    setSubmitting(false);
  };

  const handleAddHandler = async () => {
    setFormError("");
    setGlobalError("");

    const trimmed = jsonInput.trim();
    if (!trimmed) {
      setFormError("Handler configuration JSON is required");
      return;
    }

    try {
      validateHandlerConfig(trimmed);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Invalid JSON configuration");
      return;
    }

    setSubmitting(true);
    try {
      const mutation = `
        mutation {
          upsertAgentHandler(
            config: "${escapeGraphQLString(trimmed)}"
          ) {
            id
          }
        }
      `;

      const response = await sendGraphQLQuery(mutation);
      const errors = response.errors ?? response.data?.errors;
      if (errors && errors.length) {
        const message = errors[0]?.message ?? "Failed to save handler";
        setFormError(message);
        return;
      }

      if (!response.data?.data?.upsertAgentHandler?.id) {
        setFormError("Failed to save handler");
        return;
      }

      setShowAddForm(false);
      resetForm();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Failed to save handler");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteClick = (handler: AgentHandler) => {
    setHandlerToDelete(handler);
    setDeleteModalVisible(true);
  };

  const handleDeleteConfirm = async () => {
    if (!handlerToDelete) return;

    setDeleteModalVisible(false);
    setGlobalError("");
    setActionLoading((prev) => ({ ...prev, [handlerToDelete.id]: true }));

    try {
      const mutation = `
        mutation {
          deleteAgentHandler(id: "${escapeGraphQLString(handlerToDelete.id)}")
        }
      `;

      const response = await sendGraphQLQuery(mutation);
      const errors = response.errors ?? response.data?.errors;
      if (errors && errors.length) {
        const message = errors[0]?.message ?? "Failed to delete handler";
        setGlobalError(message);
        return;
      }

      if (!response.data?.data?.deleteAgentHandler) {
        setGlobalError("Failed to delete handler");
      }
    } catch (error) {
      setGlobalError(error instanceof Error ? error.message : "Failed to delete handler");
    } finally {
      setActionLoading((prev) => {
        const updated = { ...prev };
        delete updated[handlerToDelete.id];
        return updated;
      });
      setHandlerToDelete(null);
    }
  };

  const handleDeleteCancel = () => {
    setDeleteModalVisible(false);
    setHandlerToDelete(null);
  };

  return (
    <div className="listeners-container handlers-container">
      <div className="listeners-search">
        <div className="listeners-stats">
          <FaProjectDiagram className="stats-icon" />
          <span className="stats-text">{handlerList.length} Handlers</span>
          <span className="stats-text">•</span>
          <span className="stats-text">{totalCommands} Total Commands</span>
        </div>
        <button
          className="listeners-add-btn"
          onClick={() => {
            setShowAddForm(true);
            resetForm();
          }}
          disabled={submitting}
        >
          <FaPlus /> Add Handler
        </button>
      </div>

      {globalError && <div className="listeners-error">{globalError}</div>}

      {showAddForm && (
        <div className="listeners-add-form">
          <div className="listeners-form-row">
            <textarea
              value={jsonInput}
              onChange={(e) => {
                setJsonInput(e.target.value);
                setFormError("");
              }}
              placeholder='Paste handler JSON ({"agentName": "...", "agentHttpHeaderId": "...", "supportedCommands": []})'
            />
          </div>
          <div className="listeners-form-row">
            <label className="handler-upload-label">
              <FaFileUpload />
              <span>Select JSON file</span>
              <input
                type="file"
                accept="application/json"
                onChange={handleFileUpload}
              />
            </label>
            {fileName && <span className="handler-upload-filename">{fileName}</span>}
          </div>
          {formError && <div className="listeners-error">{formError}</div>}
          <div className="listeners-form-actions">
            <button
              className="listeners-save-btn"
              onClick={handleAddHandler}
              disabled={submitting}
            >
              {submitting ? "Saving..." : "Save Handler"}
            </button>
            <button
              className="listeners-cancel-btn"
              onClick={() => {
                setShowAddForm(false);
                resetForm();
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="listeners-table">
        <div className="listeners-table-header handlers-table-header">
          <span>Handler</span>
          <span>Header ID</span>
          <span>Supported Commands</span>
          <span>Actions</span>
        </div>
        <div className="listeners-table-body">
          {handlerList.map((handler) => (
            <div className="listener-row handlers-row" key={handler.id}>
              <div className="listener-name-cell">
                <FaProjectDiagram className="listener-icon" />
                <div className="listener-name-info">
                  <span className="listener-name">{handler.agentName}</span>
                  <span className="listener-description">ID: {handler.id}</span>
                </div>
              </div>
              <div className="listener-address">{handler.agentHttpHeaderId}</div>
              <div className="handler-command-list">
                {handler.supportedCommands && handler.supportedCommands.length > 0 ? (
                  handler.supportedCommands.map((command) => (
                    <span className="handler-command-chip" key={`${handler.id}-${command}`}>
                      {command}
                    </span>
                  ))
                ) : (
                  <span className="handler-empty">No commands</span>
                )}
              </div>
              <div className="listener-col-actions handler-actions">
                <button
                  className="listener-action-btn delete"
                  onClick={() => handleDeleteClick(handler)}
                  disabled={!!actionLoading[handler.id]}
                >
                  <FaTrash />
                </button>
              </div>
            </div>
          ))}
          {handlerList.length === 0 && (
            <div className="listener-row handlers-row handler-empty-row">
              <div className="listener-name-cell">
                <FaProjectDiagram className="listener-icon" />
                <div className="listener-name-info">
                  <span className="listener-name">No handlers configured</span>
                  <span className="listener-description">Add one to map agents to handler metadata</span>
                </div>
              </div>
              <div className="listener-address">—</div>
              <div className="handler-empty">Upload a JSON configuration to get started.</div>
              <div className="listener-col-actions handler-actions">—</div>
            </div>
          )}
        </div>
      </div>

      <DeleteHandlerModal
        isVisible={deleteModalVisible}
        handlerName={handlerToDelete?.agentName || ''}
        onConfirm={handleDeleteConfirm}
        onCancel={handleDeleteCancel}
      />
    </div>
  );
};

export default Handlers;
