import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { FaUpload, FaDownload, FaSpinner, FaCheckCircle, FaExclamationTriangle } from 'react-icons/fa';
import { SiOllama } from 'react-icons/si';
import './PolyEngine.css';

interface Model {
  id: string;
  name: string;
  provider?: string;
}

interface PolyEngineProps {
  isActive: boolean;
}

export default function PolyEngine({ isActive }: PolyEngineProps) {
  const [url, setUrl] = useState("");
  const [jwt, setJwt] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [models, setModels] = useState<Model[]>([]);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [selectedModel, setSelectedModel] = useState<Model | null>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [message, setMessage] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [isDragOver, setIsDragOver] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);

  // Global error handler
  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      console.error('PolyEngine global error:', event.error);
      setError('An unexpected error occurred. Please try again.');
    };

    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.error('PolyEngine unhandled promise rejection:', event.reason);
      setError('An unexpected error occurred. Please try again.');
    };

    window.addEventListener('error', handleError);
    window.addEventListener('unhandledrejection', handleUnhandledRejection);

    return () => {
      window.removeEventListener('error', handleError);
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, []);

  const normalisedOpenWebUIUrl = useMemo(() => {
    if (!url) return null;
    return url.endsWith("/") ? url : `${url}/`;
  }, [url]);

  const addLog = useCallback((message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  }, []);

  const loadModels = useCallback(async (engineUrl: string, token: string) => {
    try {
      const response = await fetch(`${engineUrl.endsWith('/') ? engineUrl : engineUrl + '/'}api/models`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to load models: ${response.status}`);
      }

      const data = await response.json();
      
      // Handle different response formats and empty cases
      let modelsArray = [];
      
      if (data === null || data === undefined) {
        // No data returned
        modelsArray = [];
      } else if (Array.isArray(data)) {
        modelsArray = data;
      } else if (data && Array.isArray(data.data)) {
        modelsArray = data.data;
      } else if (data && Array.isArray(data.models)) {
        modelsArray = data.models;
      } else if (data && typeof data === 'object') {
        // If it's an object, try to find an array property
        const possibleArrays = Object.values(data).filter(Array.isArray);
        if (possibleArrays.length > 0) {
          modelsArray = possibleArrays[0];
        }
      }
      
      // Ensure we always have an array, even if empty
      if (!Array.isArray(modelsArray)) {
        modelsArray = [];
      }
      
      setModels(modelsArray);
      
      // Show appropriate message based on result
      if (modelsArray.length === 0) {
        setError('No models available. Please ensure models are loaded in OpenWebUI.');
      }
    } catch (err) {
      console.error('Error loading models:', err);
      setError('Failed to load models - check URL and credentials');
      setModels([]);
    }
  }, []);

  // Load cached credentials on mount (same as AI component)
  useEffect(() => {
    const cachedUrl = localStorage.getItem('openwebui_url');
    const cachedJwt = localStorage.getItem('openwebui_jwt');
    if (cachedUrl && cachedJwt) {
      setUrl(cachedUrl);
      setJwt(cachedJwt);
      setIsLoggedIn(true);
      // Add error handling for loadModels
      loadModels(cachedUrl, cachedJwt).catch((err) => {
        console.error('Failed to load models on mount:', err);
        setError('Failed to load models - check URL and credentials');
      });
    }
  }, [loadModels]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      await loadModels(url, jwt);
      
      // Cache credentials (same as AI component)
      localStorage.setItem('openwebui_url', url);
      localStorage.setItem('openwebui_jwt', jwt);
      
      setIsLoggedIn(true);
    } catch (err) {
      console.error('Login failed:', err);
      setError(err instanceof Error ? err.message : 'Login failed');
      // Clear any partial state on login failure
      setIsLoggedIn(false);
      setModels([]);
      setSelectedModel(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('openwebui_url');
    localStorage.removeItem('openwebui_jwt');
    setUrl("");
    setJwt("");
    setIsLoggedIn(false);
    setModels([]);
    setSelectedModel(null);
    setUploadedFile(null);
    setMessage("");
  };

  const handleFileUpload = (file: File) => {
    setUploadedFile(file);
    setError(null);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleFileUpload(files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileUpload(files[0]);
    }
  };

  const processFile = async () => {
    if (!uploadedFile || !selectedModel || !url || !jwt) return;

    setIsProcessing(true);
    setProcessingProgress(0);
    setError(null);
    setLogs([]); // Clear previous logs

    let progressInterval: NodeJS.Timeout | null = null;

    try {
      addLog('Starting file processing...');
      setProcessingProgress(10);
      
      // Read file content
      let fileContent: string;
      try {
        addLog('Reading file content...');
        fileContent = await uploadedFile.text();
        addLog(`File read successfully (${fileContent.length} characters)`);
        setProcessingProgress(20);
      } catch (fileErr) {
        throw new Error('Failed to read file content. Please ensure the file is a valid text file.');
      }
      
      // Real progress simulation
      progressInterval = setInterval(() => {
        setProcessingProgress(prev => {
          if (prev >= 80) {
            if (progressInterval) {
              clearInterval(progressInterval);
            }
            return prev;
          }
          return prev + 5;
        });
      }, 500);

      addLog('Preparing AI request...');
      setProcessingProgress(30);
      
      // Prepare the system prompt for file rewriting with output markers
      const systemPrompt = `You are a file rewriting assistant. Your task is to rewrite the provided file content to change its hash while maintaining the same functionality and meaning. 

Rules:
1. Keep the same file structure and format
2. Maintain all functionality and behavior
3. Change variable names, comments, and formatting where possible
4. Preserve all logic and algorithms
5. Make the changes subtle but effective for hash modification
6. Do not change the file extension or core purpose

CRITICAL OUTPUT FORMAT:
You MUST wrap your rewritten file content between these exact markers:
<<<START_FILE>>>
[your rewritten file content here]
<<<END_FILE>>>

Do NOT include any explanations, thoughts, or commentary outside these markers. Everything between the markers will be extracted as the final file.
If you need to explain your changes, do so BEFORE the <<<START_FILE>>> marker.

The user may provide an optional message with specific instructions for the rewrite.`;

      // Prepare messages
      const messages = [
        { role: "system", content: systemPrompt },
        { 
          role: "user", 
          content: `Please rewrite this file to change its hash while maintaining functionality.\n\n${message ? `Additional instructions: ${message}\n\n` : ''}Remember to wrap the rewritten file between <<<START_FILE>>> and <<<END_FILE>>> markers.\n\nFile content:\n\`\`\`\n${fileContent}\n\`\`\`` 
        }
      ];

      addLog(`Sending request to AI model: ${selectedModel.name}`);
      setProcessingProgress(40);

      // Send to AI (same API as AI component)
      const response = await fetch(`${normalisedOpenWebUIUrl}api/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${jwt}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: selectedModel.id,
          messages: messages,
          stream: false,
        }),
      });

      addLog('Waiting for AI response...');
      setProcessingProgress(60);

      if (!response.ok) {
        throw new Error(`AI processing failed: ${response.status}`);
      }

      addLog('Processing AI response...');
      setProcessingProgress(70);
      
      const data = await response.json();
      
      // Validate response structure
      if (!data.choices || !Array.isArray(data.choices) || data.choices.length === 0) {
        throw new Error('Invalid response format from AI service');
      }
      
      const choice = data.choices[0];
      if (!choice.message || !choice.message.content) {
        throw new Error('No content received from AI service');
      }
      
      addLog('AI processing completed successfully');
      setProcessingProgress(80);
      
      const rewrittenContent = choice.message.content;

      // Extract content between markers
      let cleanContent = '';
      const startMarker = '<<<START_FILE>>>';
      const endMarker = '<<<END_FILE>>>';
      
      const startIndex = rewrittenContent.indexOf(startMarker);
      const endIndex = rewrittenContent.indexOf(endMarker);
      
      if (startIndex !== -1 && endIndex !== -1 && endIndex > startIndex) {
        // Extract content between markers
        cleanContent = rewrittenContent
          .substring(startIndex + startMarker.length, endIndex)
          .trim();
        addLog('Successfully extracted file content from AI response');
      } else {
        // Fallback: try to extract from markdown code blocks
        addLog('Warning: Markers not found, attempting fallback extraction...');
        const codeBlockMatch = rewrittenContent.match(/```[\s\S]*?\n([\s\S]*?)\n```/);
        if (codeBlockMatch && codeBlockMatch[1]) {
          cleanContent = codeBlockMatch[1].trim();
          addLog('Extracted content from markdown code block');
        } else {
          // Last resort: use the entire response
          cleanContent = rewrittenContent.trim();
          addLog('Warning: Using entire AI response as file content');
        }
      }

      if (!cleanContent || cleanContent.length === 0) {
        throw new Error('Failed to extract valid file content from AI response');
      }

      addLog(`Extracted ${cleanContent.length} characters of file content`);
      addLog('Preparing file download...');
      setProcessingProgress(90);

      // Download the rewritten file
      const blob = new Blob([cleanContent], { type: 'text/plain' });
      const downloadUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `rewritten_${uploadedFile.name}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(downloadUrl);

      addLog(`File downloaded successfully: rewritten_${uploadedFile.name}`);
      setProcessingProgress(100);
      
      if (progressInterval) {
        clearInterval(progressInterval);
      }

    } catch (err) {
      addLog(`Error: ${err instanceof Error ? err.message : 'Processing failed'}`);
      setError(err instanceof Error ? err.message : 'Processing failed');
    } finally {
      if (progressInterval) {
        clearInterval(progressInterval);
      }
      setIsProcessing(false);
      setProcessingProgress(0);
    }
  };

  if (!isActive) return null;

  // Safety check for critical errors
  if (error && error.includes('unexpected error')) {
    return (
      <div className="poly-engine-container">
        <div className="poly-engine-main">
          <div className="poly-engine-content">
            <div className="error-message">
              <FaExclamationTriangle />
              {error}
            </div>
            <button 
              onClick={() => {
                setError(null);
                window.location.reload();
              }}
              className="process-btn"
            >
              Reload Component
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!isLoggedIn) {
    return (
      <div className="poly-engine-container poly-engine-login-container">
        <div className="poly-engine-header">
          <div className="poly-engine-stats">
            <SiOllama className="stats-icon" />
            <span className="stats-text">Poly Engine • Not Connected</span>
          </div>
        </div>

        <div className="poly-engine-login-main">
          <div className="poly-engine-login-card">
            <div className="poly-engine-login-card-header">
              <SiOllama className="poly-engine-login-icon" />
              <h2>Connect to Open WebUI</h2>
              <p>Enter your Open WebUI endpoint and token to start processing files.</p>
            </div>

            <form className="poly-engine-login-form" onSubmit={handleLogin}>
              <div className="form-group">
                <label htmlFor="poly-url">Open WebUI URL</label>
                <input
                  id="poly-url"
                  type="url"
                  placeholder="https://your-openwebui-instance.com/"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="poly-jwt">JWT Token</label>
                <input
                  id="poly-jwt"
                  type="password"
                  placeholder="Your JWT token"
                  value={jwt}
                  onChange={(e) => setJwt(e.target.value)}
                  required
                />
              </div>

              <button type="submit" className="login-btn" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <FaSpinner className="spinner" />
                    Connecting...
                  </>
                ) : (
                  "Connect"
                )}
              </button>

              {error && <div className="error-message">{error}</div>}
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="poly-engine-container">
      <div className="poly-engine-search">
        <div className="poly-engine-stats">
          <SiOllama className="stats-icon" />
          <span className="stats-text">
            Poly Engine • {models.length} models • {selectedModel ? 'Model Selected' : 'No Model'}
          </span>
        </div>
        <button className="logout-btn" onClick={handleLogout}>
          Logout
        </button>
      </div>

      <div className="poly-engine-main">
        <div className="poly-engine-layout">
          <div className="poly-engine-left">
            <div className="model-selection">
              <h3>Select a Model</h3>
              <div className="model-dropdown">
                <select
                  value={selectedModel?.id || ""}
                  onChange={(e) => {
                    const model = Array.isArray(models) ? models.find(m => m.id === e.target.value) : null;
                    setSelectedModel(model || null);
                  }}
                >
                  <option value="">Choose a model...</option>
                  {Array.isArray(models) ? models.map((model) => (
                    <option key={model.id} value={model.id}>
                      {model.name}{" "}
                      {model.provider ? `(${model.provider})` : undefined}
                    </option>
                  )) : null}
                </select>
              </div>
            </div>

            <div className="upload-section">
              <div
                className={`upload-area ${isDragOver ? 'drag-over' : ''}`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
              >
                <FaUpload className="upload-icon" />
                <p>Drag and drop a file here, or click to select</p>
                <input
                  type="file"
                  onChange={handleFileInput}
                  className="file-input"
                  accept=".txt,.js,.py,.html,.css,.json,.xml,.md"
                />
              </div>

              {uploadedFile && (
                <div className="file-info">
                  <FaCheckCircle className="file-icon" />
                  <span>{uploadedFile.name}</span>
                  <span className="file-size">({(uploadedFile.size / 1024).toFixed(1)} KB)</span>
                </div>
              )}
            </div>

            <div className="message-section">
              <label htmlFor="message">Optional Instructions</label>
              <textarea
                id="message"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Provide specific instructions for how to rewrite the file..."
                rows={2}
              />
            </div>

            {isProcessing && (
              <div className="processing-section">
                <div className="progress-bar">
                  <div 
                    className="progress-fill" 
                    style={{ width: `${processingProgress}%` }}
                  />
                </div>
                <p>Processing file... {processingProgress}%</p>
              </div>
            )}

            {error && (
              <div className="error-message">
                <FaExclamationTriangle />
                {error}
              </div>
            )}

            <div className="button-container">
              <button
                className="process-btn"
                onClick={processFile}
                disabled={!uploadedFile || !selectedModel || isProcessing}
              >
                {isProcessing ? (
                  <>
                    <FaSpinner className="spinner" />
                    Processing...
                  </>
                ) : (
                  <>
                    <FaDownload />
                    Process & Download
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="poly-engine-logs">
            <h3>Processing Logs</h3>
            <div className="poly-engine-logs-container">
              {logs.length === 0 ? (
                <p className="poly-engine-logs-empty">No logs yet. Start processing a file to see logs here.</p>
              ) : (
                logs.map((log, index) => (
                  <div key={index} className="poly-engine-log-entry">
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
