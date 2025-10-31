import React from 'react';
import { FaTrash, FaTimes, FaExclamationTriangle } from 'react-icons/fa';
import './DeleteScriptModal.css';

interface DeleteListenerModalProps {
  isVisible: boolean;
  listenerName: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function DeleteListenerModal({ 
  isVisible, 
  listenerName, 
  onConfirm, 
  onCancel 
}: DeleteListenerModalProps) {
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      onConfirm();
    } else if (e.key === 'Escape') {
      onCancel();
    }
  };

  if (!isVisible) return null;

  return (
    <div className="delete-script-modal-overlay" onKeyDown={handleKeyDown}>
      <div className="delete-script-modal">
        <div className="delete-script-modal-header">
          <h3>Delete Listener</h3>
          <button className="delete-script-modal-close" onClick={onCancel}>
            <FaTimes />
          </button>
        </div>

        <div className="delete-script-modal-content">
          <div className="delete-script-warning">
            <FaExclamationTriangle className="delete-warning-icon" />
            <div className="delete-warning-text">
              <div className="warning-title">Are you sure?</div>
              <div className="warning-message">
                This will permanently delete the listener <strong>"{listenerName}"</strong>. 
                Agents using this listener will be unable to connect. This action cannot be undone.
              </div>
            </div>
          </div>

          <div className="delete-script-actions">
            <button
              className="delete-script-cancel"
              onClick={onCancel}
            >
              Cancel
            </button>
            <button
              className="delete-script-confirm"
              onClick={onConfirm}
            >
              <FaTrash />
              Delete Listener
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

