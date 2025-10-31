import React, { useState, useEffect } from 'react';
import { FaSyringe, FaTimes, FaCheckCircle } from 'react-icons/fa';

interface ShellcodeInjectModalProps {
  isVisible: boolean;
  fileName: string;
  agentName: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ShellcodeInjectModal({ 
  isVisible, 
  fileName, 
  agentName, 
  onConfirm, 
  onCancel 
}: ShellcodeInjectModalProps) {
  const [isInjecting, setIsInjecting] = useState(false);

  // Reset form when modal opens
  useEffect(() => {
    if (isVisible) {
      setIsInjecting(false);
    }
  }, [isVisible]);

  const handleConfirm = () => {
    setIsInjecting(true);
    onConfirm();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isInjecting) {
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
          <h3>Inject Shellcode into Agent</h3>
          <button className="file-upload-modal-close" onClick={onCancel}>
            <FaTimes />
          </button>
        </div>

        <div className="file-upload-modal-content">
          <div className="file-upload-info">
            <FaSyringe className="file-upload-icon" />
            <div className="file-upload-details">
              <div className="file-name">{fileName}</div>
              <div className="agent-name">Target: {agentName}</div>
            </div>
          </div>

          <div className="file-upload-form">
            <small className="file-upload-help shellcode-warning">
              ⚠️ Warning: This will inject the selected shellcode into the agent process.
              Make sure the shellcode is valid and properly formatted as hex.
            </small>
          </div>

          <div className="file-upload-actions">
            <button
              className="file-upload-cancel"
              onClick={onCancel}
              disabled={isInjecting}
            >
              Cancel
            </button>
            <button
              className="file-upload-confirm shellcode-inject-btn"
              onClick={handleConfirm}
              disabled={isInjecting}
            >
              {isInjecting ? (
                <>
                  <FaCheckCircle className="uploading-icon" />
                  Injecting...
                </>
              ) : (
                <>
                  <FaSyringe />
                  Inject Shellcode
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

