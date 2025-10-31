import React from 'react';
import { FaTrash, FaTimes, FaExclamationTriangle } from 'react-icons/fa';
import './DeleteScriptModal.css';

interface DeleteHandlerModalProps {
  isVisible: boolean;
  handlerName: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function DeleteHandlerModal({ 
  isVisible, 
  handlerName, 
  onConfirm, 
  onCancel 
}: DeleteHandlerModalProps) {
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
          <h3>Delete Handler</h3>
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
                This will permanently delete the handler <strong>"{handlerName}"</strong>. 
                This action cannot be undone.
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
              Delete Handler
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

