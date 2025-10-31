import React, { useState, useEffect } from 'react';
import { FaUpload, FaTimes, FaCheckCircle, FaEdit } from 'react-icons/fa';

interface FileUploadModalProps {
  isVisible: boolean;
  fileName: string;
  agentName: string;
  onConfirm: (remotePath: string) => void;
  onCancel: () => void;
}

export default function FileUploadModal({ 
  isVisible, 
  fileName, 
  agentName, 
  onConfirm, 
  onCancel 
}: FileUploadModalProps) {
  const [remotePath, setRemotePath] = useState(fileName);
  const [isUploading, setIsUploading] = useState(false);
  const [showPathInput, setShowPathInput] = useState(false);

  // Reset form when modal opens
  useEffect(() => {
    if (isVisible) {
      setRemotePath(fileName);
      setIsUploading(false);
      setShowPathInput(false); // Start with simple view
    }
  }, [isVisible, fileName]);

  const handleConfirm = () => {
    const pathToUse = remotePath.trim() || fileName;
    setIsUploading(true);
    onConfirm(pathToUse);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isUploading) {
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
          <h3>Upload File to Agent</h3>
          <button className="file-upload-modal-close" onClick={onCancel} disabled={isUploading}>
            <FaTimes />
          </button>
        </div>

        <div className="file-upload-modal-content">
          <div className="file-upload-info">
            <FaUpload className="file-upload-icon" />
            <div className="file-upload-details">
              <div className="file-name">{fileName}</div>
              <div className="agent-name">Target: {agentName}</div>
            </div>
          </div>

          {showPathInput ? (
            <div className="file-upload-form">
              <label htmlFor="remote-path">Remote File Path</label>
              <input
                id="remote-path"
                type="text"
                value={remotePath}
                onChange={(e) => setRemotePath(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Enter remote file path (e.g., /tmp/file.txt or C:\temp\file.txt)"
                className="file-upload-input"
                disabled={isUploading}
                autoFocus
              />
              <small className="file-upload-help">
                Will upload to current directory with this filename
              </small>
            </div>
          ) : (
            <div className="file-upload-simple-info">
              <small className="file-upload-help">
                File will be uploaded to the agent's current directory as <strong>{fileName}</strong>
              </small>
              <button
                className="file-upload-edit-path"
                onClick={() => setShowPathInput(true)}
                disabled={isUploading}
              >
                <FaEdit /> Customize Path
              </button>
            </div>
          )}

          <div className="file-upload-actions">
            <button
              className="file-upload-cancel"
              onClick={onCancel}
              disabled={isUploading}
            >
              Cancel
            </button>
            <button
              className="file-upload-confirm"
              onClick={handleConfirm}
              disabled={isUploading}
            >
              {isUploading ? (
                <>
                  <FaCheckCircle className="uploading-icon" />
                  Uploading...
                </>
              ) : (
                <>
                  <FaUpload />
                  Upload File
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
