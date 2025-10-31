import React, { useState, useRef, useCallback, useEffect } from 'react';
import { FaUpload, FaFile, FaTimes, FaCheckCircle, FaGripVertical } from 'react-icons/fa';

interface FileUploadProps {
  onFileSelect: (file: File, remotePath: string) => void;
  onClose: () => void;
  isVisible: boolean;
}

export default function FileUpload({ onFileSelect, onClose, isVisible }: FileUploadProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [remotePath, setRemotePath] = useState<string>('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [modalPosition, setModalPosition] = useState({ x: 0, y: 0 });
  const fileInputRef = useRef<HTMLInputElement>(null);
  const modalRef = useRef<HTMLDivElement>(null);

  const handleFileSelect = useCallback((file: File) => {
    setSelectedFile(file);
    // Set default remote path to just the filename
    if (!remotePath) {
      setRemotePath(file.name);
    }
  }, [remotePath]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleFileSelect(files[0]);
    }
  }, [handleFileSelect]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  }, [handleFileSelect]);

  const handleUpload = useCallback(async () => {
    if (!selectedFile || !remotePath.trim()) {
      return;
    }

    setIsUploading(true);
    
    try {
      // Convert file to base64
      const base64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const result = reader.result as string;
          // Remove data URL prefix to get just the base64 data
          const base64Data = result.split(',')[1];
          resolve(base64Data);
        };
        reader.onerror = reject;
        reader.readAsDataURL(selectedFile);
      });

      // Call the onFileSelect callback with the file and remote path
      onFileSelect(selectedFile, remotePath.trim());
      
      // Reset form
      setSelectedFile(null);
      setRemotePath('');
      onClose();
    } catch (error) {
      console.error('Failed to process file:', error);
    } finally {
      setIsUploading(false);
    }
  }, [selectedFile, remotePath, onFileSelect, onClose]);

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Drag functionality for modal
  const handleModalMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.target === modalRef.current || (e.target as HTMLElement).closest('.file-upload-header')) {
      setIsDragging(true);
      const rect = modalRef.current?.getBoundingClientRect();
      if (rect) {
        setDragOffset({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top
        });
      }
    }
  }, []);

  const handleModalMouseMove = useCallback((e: MouseEvent) => {
    if (isDragging) {
      const newX = e.clientX - dragOffset.x;
      const newY = e.clientY - dragOffset.y;
      
      // Keep modal within viewport bounds
      const maxX = window.innerWidth - (modalRef.current?.offsetWidth || 500);
      const maxY = window.innerHeight - (modalRef.current?.offsetHeight || 400);
      
      setModalPosition({
        x: Math.max(0, Math.min(newX, maxX)),
        y: Math.max(0, Math.min(newY, maxY))
      });
    }
  }, [isDragging, dragOffset]);

  const handleModalMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mousemove', handleModalMouseMove);
      document.addEventListener('mouseup', handleModalMouseUp);
      
      return () => {
        document.removeEventListener('mousemove', handleModalMouseMove);
        document.removeEventListener('mouseup', handleModalMouseUp);
      };
    }
  }, [isDragging, handleModalMouseMove, handleModalMouseUp]);

  // Reset position when modal opens
  useEffect(() => {
    if (isVisible) {
      setModalPosition({ x: 0, y: 0 });
    }
  }, [isVisible]);

  if (!isVisible) return null;

  return (
    <div className="file-upload-overlay">
      <div 
        ref={modalRef}
        className="file-upload-modal"
        style={{
          transform: modalPosition.x !== 0 || modalPosition.y !== 0 
            ? `translate(${modalPosition.x}px, ${modalPosition.y}px)` 
            : undefined
        }}
        onMouseDown={handleModalMouseDown}
      >
        <div className="file-upload-header">
          <div className="file-upload-drag-handle">
            <FaGripVertical />
          </div>
          <h3>Upload File to Agent</h3>
          <button className="file-upload-close" onClick={onClose}>
            <FaTimes />
          </button>
        </div>

        <div className="file-upload-content">
          <div className="file-upload-section">
            <label>Select File</label>
            <div
              className={`file-upload-area ${isDragOver ? 'drag-over' : ''}`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <FaUpload className="upload-icon" />
              <p>Drag and drop a file here, or click to select</p>
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileInput}
                className="file-input-hidden"
                accept="*/*"
              />
            </div>

            {selectedFile && (
              <div className="file-info">
                <FaFile className="file-icon" />
                <div className="file-details">
                  <span className="file-name">{selectedFile.name}</span>
                  <span className="file-size">{formatFileSize(selectedFile.size)}</span>
                </div>
              </div>
            )}
          </div>

          <div className="file-upload-section">
            <label htmlFor="remote-path">Remote File Path</label>
            <input
              id="remote-path"
              type="text"
              value={remotePath}
              onChange={(e) => setRemotePath(e.target.value)}
              placeholder="Enter remote file path (e.g., /tmp/uploaded_file.txt)"
              className="file-upload-input"
            />
            <small className="file-upload-help">
              Path where the file will be saved on the agent. Can be relative to current directory or absolute.
            </small>
          </div>

          <div className="file-upload-actions">
            <button
              className="file-upload-cancel"
              onClick={onClose}
              disabled={isUploading}
            >
              Cancel
            </button>
            <button
              className="file-upload-submit"
              onClick={handleUpload}
              disabled={!selectedFile || !remotePath.trim() || isUploading}
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
