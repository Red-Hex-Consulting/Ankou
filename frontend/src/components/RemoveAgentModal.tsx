import React, { useState, useEffect } from 'react';
import { FaTrashAlt, FaTimes, FaCheckCircle, FaExclamationTriangle } from 'react-icons/fa';

interface RemoveAgentModalProps {
  isVisible: boolean;
  agentName: string;
  agentId: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function RemoveAgentModal({ 
  isVisible, 
  agentName,
  agentId,
  onConfirm, 
  onCancel 
}: RemoveAgentModalProps) {
  const [isRemoving, setIsRemoving] = useState(false);

  useEffect(() => {
    if (isVisible) {
      setIsRemoving(false);
    }
  }, [isVisible]);

  const handleConfirm = () => {
    setIsRemoving(true);
    onConfirm();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isRemoving) {
      handleConfirm();
    } else if (e.key === 'Escape') {
      onCancel();
    }
  };

  if (!isVisible) return null;

  return (
    <div className="file-upload-modal-overlay" onKeyDown={handleKeyDown}>
      <div className="file-upload-modal">
        <div className="file-upload-modal-header">
          <h3>Remove Agent</h3>
          <button className="file-upload-modal-close" onClick={onCancel}>
            <FaTimes />
          </button>
        </div>

        <div className="file-upload-modal-content">
          <div className="file-upload-info">
            <FaTrashAlt className="file-upload-icon remove-agent-icon" />
            <div className="file-upload-details">
              <div className="file-name">{agentName || 'Unknown Agent'}</div>
              <div className="agent-name">ID: {agentId}</div>
            </div>
          </div>

          <div className="file-upload-form">
            <small className="file-upload-help remove-agent-warning">
              <FaExclamationTriangle className="warning-icon" /> Are you sure you want to remove this agent from the dashboard?
              <br /><br />
              <strong>Note:</strong> Agent data (command history, loot files) will be preserved in the database. 
              The agent will simply be hidden from view.
            </small>
          </div>

          <div className="file-upload-actions">
            <button
              className="file-upload-cancel"
              onClick={onCancel}
              disabled={isRemoving}
            >
              Cancel
            </button>
            <button
              className="file-upload-confirm remove-agent-btn"
              onClick={handleConfirm}
              disabled={isRemoving}
            >
              {isRemoving ? (
                <>
                  <FaCheckCircle className="uploading-icon" />
                  Removing...
                </>
              ) : (
                <>
                  <FaTrashAlt />
                  Remove Agent
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

