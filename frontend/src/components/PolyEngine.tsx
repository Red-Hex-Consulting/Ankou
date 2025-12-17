import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { FaUpload, FaDownload, FaSpinner, FaCheckCircle, FaExclamationTriangle, FaTimes } from 'react-icons/fa';
import { FiCheck, FiX, FiCheckCircle } from 'react-icons/fi';
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

const API_BASE_URL_STORAGE_KEY = "ai_api_base_url";
const API_KEY_STORAGE_KEY = "ai_api_key";
const DEFAULT_API_BASE_URL = "http://localhost:11434/v1";

export default function PolyEngine({ isActive }: PolyEngineProps) {
  const [apiBaseUrl, setApiBaseUrl] = useState(DEFAULT_API_BASE_URL);
  const [apiKey, setApiKey] = useState("");
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
  const [logs, setLogs] = useState<Array<{message: string, type?: 'success' | 'error' | 'complete' | 'info'}>>([]);
  const [abortController, setAbortController] = useState<AbortController | null>(null);
  const [useToolCalling, setUseToolCalling] = useState(true);

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

  const normalizedApiBaseUrl = useMemo(() => {
    if (!apiBaseUrl) return null;
    return apiBaseUrl.replace(/\/+$/, "");
  }, [apiBaseUrl]);

  const addLog = useCallback((message: string, type?: 'success' | 'error' | 'complete' | 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { message: `[${timestamp}] ${message}`, type: type || 'info' }]);
  }, []);

  const loadModels = useCallback(async (engineUrl: string, token?: string) => {
    try {
      const baseUrl = engineUrl.trim().replace(/\/+$/, "");
      if (!baseUrl) {
        throw new Error("API base URL is required.");
      }
      const headers: Record<string, string> = {
        Accept: "application/json",
        "Content-Type": "application/json",
      };
      if (token?.trim()) {
        headers.Authorization = `Bearer ${token.trim()}`;
      }

      const response = await fetch(`${baseUrl}/models`, {
        method: "GET",
        headers,
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
      
      const normalizedModels: Model[] = modelsArray.map((model: any) => ({
        id: model.id || model.name,
        name: model.name || model.id,
        provider: model.provider || model.source,
      }));

      setModels(normalizedModels);
      
      // Show appropriate message based on result
      if (modelsArray.length === 0) {
        setError('No models available. Please ensure your OpenAI-compatible endpoint exposes a model list.');
      }
    } catch (err) {
      console.error('Error loading models:', err);
      setError('Failed to load models - check the API base URL and API key');
      setModels([]);
    }
  }, []);

  // Load cached credentials on mount (same as AI component)
  useEffect(() => {
    const cachedUrl = localStorage.getItem(API_BASE_URL_STORAGE_KEY);
    const cachedKey = localStorage.getItem(API_KEY_STORAGE_KEY) || "";
    if (cachedUrl) {
      setApiBaseUrl(cachedUrl);
    } else {
      setApiBaseUrl(DEFAULT_API_BASE_URL);
    }
    if (cachedKey) {
      setApiKey(cachedKey);
    }
    if (cachedUrl) {
      setIsLoggedIn(true);
      loadModels(cachedUrl, cachedKey).catch((err) => {
        console.error('Failed to load models on mount:', err);
        setError('Failed to load models - check the API base URL and API key');
      });
    }
  }, [loadModels]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const baseUrl = apiBaseUrl.trim().replace(/\/+$/, "");
      if (!baseUrl) {
        throw new Error("Please provide an API base URL.");
      }

      await loadModels(baseUrl, apiKey);
      
      // Cache credentials (shared with AI component)
      localStorage.setItem(API_BASE_URL_STORAGE_KEY, baseUrl);
      if (apiKey.trim()) {
        localStorage.setItem(API_KEY_STORAGE_KEY, apiKey.trim());
      } else {
        localStorage.removeItem(API_KEY_STORAGE_KEY);
      }
      
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
    localStorage.removeItem(API_BASE_URL_STORAGE_KEY);
    localStorage.removeItem(API_KEY_STORAGE_KEY);
    setApiBaseUrl(DEFAULT_API_BASE_URL);
    setApiKey("");
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

  const processFileWithTools = async (
    fileContent: string,
    controller: AbortController,
    fileName: string,
    baseUrl: string,
    authToken?: string
  ) => {
    // Define tools for the AI to edit the file
    const tools = [
      {
        type: "function",
        function: {
          name: "replace_text",
          description: "Replace a specific text string in the file with new text. Use this to change variable names, function names, string literals, or any other text.",
          parameters: {
            type: "object",
            properties: {
              old_text: {
                type: "string",
                description: "The exact text to find and replace. Must be unique enough to match only the intended location."
              },
              new_text: {
                type: "string",
                description: "The new text to replace it with"
              },
              description: {
                type: "string",
                description: "Brief description of what this change does (e.g., 'rename variable foo to bar')"
              }
            },
            required: ["old_text", "new_text", "description"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "insert_text",
          description: "Insert new text after a specific anchor string. Use this to add comments, new lines, or other additions.",
          parameters: {
            type: "object",
            properties: {
              after: {
                type: "string",
                description: "The anchor text to insert after. Must be unique."
              },
              text: {
                type: "string",
                description: "The text to insert"
              },
              description: {
                type: "string",
                description: "Brief description of what this change does"
              }
            },
            required: ["after", "text", "description"]
          }
        }
      }
    ];

    const systemPrompt = `You are a code transformation engine for security tooling. Your job is to modify code to change its hash while maintaining EXACT functionality.

CRITICAL - DO NOT CHANGE:
- API endpoints, URLs, or network addresses
- Serialization formats or data structures (e.g., JSON keys, protocol formats, markers like "LOOT_ENTRIES")
- Control flow or logic
- Function signatures or interfaces
- Import statements or dependencies
- Cryptographic operations or keys
- Any hardcoded values that affect runtime behavior

SAFE CHANGES (High Confidence Only):
1. For scripting languages (JavaScript, Python, PHP):
   - Rename local variables to synonyms (e.g., userData → userInfo, count → total)
   - Modify or add comments with different wording
   - Reorder independent function declarations
   - Change quote styles (' vs ") where it doesn't affect functionality

2. For compiled languages (Go, Rust, C/C++, etc.):
   - Reorder independent function/struct declarations
   - Add or modify whitespace and formatting
   - Reorder import statements (if language allows)
   - Rename unexported/private variables ONLY if highly confident

3. Universal safe changes:
   - Reorder independent code blocks (functions, classes)
   - Adjust indentation or formatting
   - Add blank lines between sections

Make 3-5 HIGH CONFIDENCE changes only. Quality over quantity. When in doubt, skip the change.

WORKFLOW:
1. Analyze the file and identify 3-5 safe changes
2. Call replace_text or insert_text for EACH change
3. When done making changes, simply stop calling tools

Example:
- replace_text(old="userData", new="userInfo", description="rename variable")
- replace_text(old="count", new="total", description="rename counter")
- replace_text(old="fetchData", new="retrieveData", description="rename function")
- (no more tool calls - done)

Each tool call is applied sequentially. Be precise and conservative.`;

    // Detect file type
    const fileExt = fileName.split('.').pop()?.toLowerCase() || 'unknown';
    const isScriptingLanguage = ['js', 'jsx', 'ts', 'tsx', 'py', 'php', 'rb', 'pl'].includes(fileExt);
    const languageContext = isScriptingLanguage 
      ? `This is a .${fileExt} file (scripting language). Variable/function renaming is safe.`
      : `This is a .${fileExt} file. Use conservative transforms only (reordering, formatting).`;

    let currentContent = fileContent;
    const conversationMessages: any[] = [
      { role: "system", content: systemPrompt },
      {
        role: "user",
        content: `${message ? `Additional requirements: ${message}\n\n` : ''}${languageContext}\n\nAnalyze this file and make 3-5 conservative changes:\n1. Call replace_text or insert_text for each change\n2. When done, simply stop calling tools\n\nMake all your changes in your first response.\n\nFile (${fileContent.length} characters):\n\`\`\`\n${fileContent}\n\`\`\``
      }
    ];

    let iterationCount = 0;
    const maxIterations = 2; // Allow 1 retry if AI doesn't use tools initially
    let isFinished = false;
    let changeCount = 0;

    addLog('Using tool-calling mode for intelligent file editing');
    addLog(`File size: ${fileContent.length} characters`);
    addLog(languageContext);

    while (iterationCount < maxIterations && !isFinished) {
      iterationCount++;
      setProcessingProgress(30 + (iterationCount * 30));

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (authToken?.trim()) {
        headers.Authorization = `Bearer ${authToken.trim()}`;
      }

      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: selectedModel.id,
          messages: conversationMessages,
          tools: tools,
          tool_choice: "auto",
          stream: false,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`AI processing failed: ${response.status}`);
      }

      let data;
      try {
        data = await response.json();
      } catch (parseErr) {
        addLog('Failed to parse AI response. Model may not be compatible.', 'error');
        throw new Error('TOOL_CALLING_NOT_SUPPORTED');
      }
      
      // Check if model doesn't support tool calling
      if (!data || !data.choices || data.choices.length === 0) {
        addLog('Model does not support tool calling. Switching to legacy mode...', 'error');
        throw new Error('TOOL_CALLING_NOT_SUPPORTED');
      }
      
      const choice = data.choices[0];
      
      if (!choice || !choice.message) {
        throw new Error('Invalid response from AI service');
      }

      const assistantMessage = choice.message;
      conversationMessages.push(assistantMessage);

      // Check if AI wants to call tools
      if (assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0) {
        for (const toolCall of assistantMessage.tool_calls) {
          const functionName = toolCall.function.name;
          const args = JSON.parse(toolCall.function.arguments);

          if (functionName === "replace_text") {
            const { old_text, new_text, description } = args;
            let success = false;
            let responseMessage = "";
            
            if (!old_text || !new_text) {
              addLog('Invalid replace_text call: missing old_text or new_text', 'error');
              responseMessage = "Failed: missing required parameters";
            } else if (currentContent.includes(old_text)) {
              currentContent = currentContent.replace(old_text, new_text);
              addLog(description || 'Text replaced', 'success');
              changeCount++;
              success = true;
              responseMessage = "Success: text replaced";
            } else {
              const preview = old_text.length > 50 ? old_text.substring(0, 50) + '...' : old_text;
              addLog(`Could not find text to replace: "${preview}"`, 'error');
              responseMessage = `Failed: could not find old_text in file`;
            }
            
            conversationMessages.push({
              role: "tool",
              tool_call_id: toolCall.id,
              content: responseMessage
            });
          } else if (functionName === "insert_text") {
            const { after, text, description } = args;
            let success = false;
            let responseMessage = "";
            
            if (!after || !text) {
              addLog('Invalid insert_text call: missing after or text', 'error');
              responseMessage = "Failed: missing required parameters";
            } else if (currentContent.includes(after)) {
              currentContent = currentContent.replace(after, after + text);
              addLog(description || 'Text inserted', 'success');
              changeCount++;
              success = true;
              responseMessage = "Success: text inserted";
            } else {
              const preview = after.length > 50 ? after.substring(0, 50) + '...' : after;
              addLog(`Could not find anchor text: "${preview}"`, 'error');
              responseMessage = "Failed: could not find anchor text in file";
            }
            
            conversationMessages.push({
              role: "tool",
              tool_call_id: toolCall.id,
              content: responseMessage
            });
          }
        }
      } else {
        // AI stopped calling tools - we're done
        if (iterationCount === 1 && changeCount === 0) {
          addLog('AI did not use tools. Prompting to use them...');
          conversationMessages.push({
            role: "user",
            content: "You must use the provided tools (replace_text, insert_text) to edit the file. Make 3-5 changes."
          });
        } else {
          // AI finished making changes
          if (changeCount > 0) {
            addLog(`Completed with ${changeCount} changes applied`, 'complete');
          } else {
            addLog('No changes were made to the file');
          }
          isFinished = true;
        }
      }

      if (iterationCount >= maxIterations && !isFinished) {
        if (changeCount > 0) {
          addLog(`Completed with ${changeCount} changes applied`, 'complete');
        } else {
          addLog('Completed with no changes');
        }
        isFinished = true;
      }
    }

    return currentContent;
  };

  const processFile = async () => {
    if (!uploadedFile || !selectedModel || !apiBaseUrl.trim()) return;

    setIsProcessing(true);
    setProcessingProgress(0);
    setError(null);
    setLogs([]); // Clear previous logs

    // Create abort controller for this processing session
    const controller = new AbortController();
    setAbortController(controller);

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

      let cleanContent = '';

      // Detect file type info
      const fileExt = uploadedFile.name.split('.').pop()?.toLowerCase() || '';
      const isScriptingLanguage = ['js', 'jsx', 'ts', 'tsx', 'py', 'php', 'rb', 'pl'].includes(fileExt);
      
      const baseUrl = normalizedApiBaseUrl || apiBaseUrl.trim().replace(/\/+$/, "");
      if (!baseUrl) {
        throw new Error("API base URL is not configured.");
      }
      const authToken = apiKey.trim() || undefined;

      if (useToolCalling) {
        // Use tool-calling mode for more reliable editing
        try {
          cleanContent = await processFileWithTools(
            fileContent,
            controller,
            uploadedFile.name,
            baseUrl,
            authToken
          );
          setProcessingProgress(90);
        } catch (toolErr) {
          // Check if model doesn't support tool calling
          if (toolErr instanceof Error && toolErr.message === 'TOOL_CALLING_NOT_SUPPORTED') {
            addLog('Falling back to legacy mode (full file rewrite)...');
            // Fall through to legacy mode below
          } else {
            throw toolErr; // Re-throw other errors
          }
        }
      }
      
      if (!cleanContent) {
        // Legacy mode: full file rewrite
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

        // Prepare file type context for AI
        const languageContext = isScriptingLanguage 
          ? `This is a .${fileExt} file (scripting language). Variable/function renaming is safe.`
          : `This is a .${fileExt} file. Use conservative transforms only (reordering, formatting).`;
        
        addLog('Preparing AI request...');
        addLog(languageContext);
        setProcessingProgress(30);
      
        // Prepare the system prompt for file rewriting with output markers
      const systemPrompt = `You are a code transformation engine for security tooling. Your ONLY job is to output rewritten code that changes the file hash while maintaining EXACT functionality.

CRITICAL - NEVER CHANGE:
- API endpoints, URLs, network addresses
- Serialization formats (JSON keys, protocol data, markers like "LOOT_ENTRIES")
- Control flow, logic, or algorithms
- Function signatures, interfaces, or exports
- Import statements or dependencies
- Cryptographic operations, keys, or HMAC values
- Hardcoded values affecting runtime behavior (timeouts, buffer sizes, etc.)

SAFE CHANGES ONLY (High Confidence):
1. For scripting languages (JS, Python, PHP):
   - Rename local variables to synonyms (userData → userInfo)
   - Modify/add comments with different wording
   - Change quote styles where safe (' vs ")
   - Reorder independent function declarations

2. For compiled languages (Go, Rust, C/C++):
   - Reorder independent functions/structs
   - Adjust whitespace and formatting
   - Add blank lines between sections
   - Rename unexported/private identifiers ONLY if certain

3. Universal:
   - Reorder independent code blocks
   - Adjust indentation/formatting
   - Add whitespace

Make CONSERVATIVE changes. Quality over quantity. When uncertain, keep original.

REQUIRED OUTPUT FORMAT:
<<<START_FILE>>>
[complete rewritten file - no explanations, just code]
<<<END_FILE>>>

EXAMPLE (Python):
Input:
def fetch(url):
    data = download(url)
    return data

Output:
<<<START_FILE>>>
def fetch(url):
    # Retrieve data from URL
    result = download(url)
    return result
<<<END_FILE>>>

Output ONLY the markers and complete rewritten code. No explanations before or after.`;

        // Prepare initial messages with file type context
        const conversationMessages = [
          { role: "system", content: systemPrompt },
          { 
            role: "user", 
            content: `${message ? `Additional requirements: ${message}\n\n` : ''}${languageContext}\n\nRewrite this file now making CONSERVATIVE changes only. Output ONLY the <<<START_FILE>>> marker, the complete rewritten code, and <<<END_FILE>>> marker. No explanations.\n\nFile to rewrite:\n\`\`\`\n${fileContent}\n\`\`\`` 
          }
        ];

        let retryCount = 0;
        const maxRetries = 5;

        // Retry loop for getting proper formatted output
        while (retryCount < maxRetries && !cleanContent) {
          if (retryCount > 0) {
            addLog(`Retry attempt ${retryCount}/${maxRetries} - asking AI to provide complete code...`);
          } else {
            addLog(`Sending request to AI model: ${selectedModel.name}`);
            addLog(`Original file size: ${fileContent.length} characters`);
          }
          
          setProcessingProgress(40 + (retryCount * 10));

          // Send to AI (same API as AI component)
          const headers: Record<string, string> = {
            'Content-Type': 'application/json',
          };
          if (authToken?.trim()) {
            headers.Authorization = `Bearer ${authToken.trim()}`;
          }

          const response = await fetch(`${baseUrl}/chat/completions`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
              model: selectedModel.id,
              messages: conversationMessages,
              stream: false,
            }),
            signal: controller.signal,
          });

          addLog('Waiting for AI response...');
          setProcessingProgress(60 + (retryCount * 5));

          if (!response.ok) {
            throw new Error(`AI processing failed: ${response.status}`);
          }

          addLog('Processing AI response...');
          setProcessingProgress(70);
          
          let data;
          try {
            data = await response.json();
          } catch (parseErr) {
            throw new Error('Failed to parse AI response. The model may have returned invalid data.');
          }
          
          // Validate response structure
          if (!data || !data.choices || !Array.isArray(data.choices) || data.choices.length === 0) {
            throw new Error('Invalid response format from AI service. The model may not be compatible.');
          }
          
          const choice = data.choices[0];
          if (!choice || !choice.message || !choice.message.content) {
            throw new Error('No content received from AI service');
          }
          
          const rewrittenContent = choice.message.content;
          
          // Add assistant's response to conversation history
          conversationMessages.push({ role: "assistant", content: rewrittenContent });

          // Try to extract content between markers
          const startMarker = '<<<START_FILE>>>';
          const endMarker = '<<<END_FILE>>>';
          
          const startIndex = rewrittenContent.indexOf(startMarker);
          const endIndex = rewrittenContent.indexOf(endMarker);
          
          if (startIndex !== -1 && endIndex !== -1 && endIndex > startIndex) {
            // Extract content between markers
            cleanContent = rewrittenContent
              .substring(startIndex + startMarker.length, endIndex)
              .trim();
            addLog(`Extracted content between markers (${cleanContent.length} characters)`);
          } else {
            // Try fallback extraction methods
            addLog('Markers not found, attempting fallback extraction...');
            const codeBlockMatch = rewrittenContent.match(/```[\s\S]*?\n([\s\S]*?)\n```/);
            if (codeBlockMatch && codeBlockMatch[1]) {
              cleanContent = codeBlockMatch[1].trim();
              addLog(`Extracted content from markdown code block (${cleanContent.length} characters)`);
            }
          }

          // Validate the extracted content is reasonable
          const minExpectedSize = Math.min(fileContent.length * 0.5, 100); // At least 50% of original or 100 chars minimum
          const isContentTooSmall = cleanContent.length < minExpectedSize;
          const looksLikeExplanation = cleanContent.length < 500 && (
            cleanContent.toLowerCase().includes('here is') ||
            cleanContent.toLowerCase().includes('here\'s') ||
            cleanContent.toLowerCase().includes('i have') ||
            cleanContent.toLowerCase().includes('i\'ve') ||
            cleanContent.toLowerCase().startsWith('and') ||
            cleanContent.toLowerCase().startsWith('the ')
          );

          if (!cleanContent || cleanContent.length === 0 || isContentTooSmall || looksLikeExplanation) {
            if (retryCount < maxRetries - 1) {
              if (!cleanContent || cleanContent.length === 0) {
                addLog('Empty response received, retrying...');
              } else if (isContentTooSmall) {
                addLog(`Content too small (${cleanContent.length} chars vs expected ~${fileContent.length}), retrying...`);
              } else if (looksLikeExplanation) {
                addLog(`Response appears to be text/explanation ("${cleanContent.substring(0, 50)}..."), not code. Retrying...`);
              }
              
              // Add the AI's response to conversation and ask for correction
              let retryMessage = "STOP. Your previous response was invalid. ";
              if (!cleanContent || cleanContent.length === 0) {
                retryMessage += "You provided no code. ";
              } else if (isContentTooSmall) {
                retryMessage += `You only provided ${cleanContent.length} characters but the file is ${fileContent.length} characters long. `;
              } else if (looksLikeExplanation) {
                retryMessage += "You provided an explanation, not code. ";
              }
              retryMessage += `\n\nYou MUST rewrite the ENTIRE file (${fileContent.length} characters) and output it between these markers:\n<<<START_FILE>>>\n[COMPLETE rewritten code here]\n<<<END_FILE>>>\n\nDo it now. No text before or after the markers.`;
              
              conversationMessages.push({
                role: "user",
                content: retryMessage
              });
              retryCount++;
              cleanContent = ''; // Reset for next attempt
              continue;
            } else {
              // Last retry failed
              if (!cleanContent || cleanContent.length === 0) {
                throw new Error('Failed to extract valid file content from AI response after multiple attempts');
              } else {
                addLog('Warning: Content may be incomplete or invalid, but using it as last resort');
              }
            }
          }

          // Successfully extracted valid content
          addLog('Successfully validated extracted content');
          break;
        }

        addLog('AI processing completed successfully');
        addLog(`Extracted ${cleanContent.length} characters of file content`);
        setProcessingProgress(90);
      }

      // Common download logic for both modes
      addLog('Preparing file download...');
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
      // Check if it was aborted by user
      if (err instanceof Error && err.name === 'AbortError') {
        addLog('Processing stopped by user');
        setError('Processing stopped by user');
      } else {
        addLog(`Error: ${err instanceof Error ? err.message : 'Processing failed'}`);
        setError(err instanceof Error ? err.message : 'Processing failed');
      }
    } finally {
      if (progressInterval) {
        clearInterval(progressInterval);
      }
      setIsProcessing(false);
      setProcessingProgress(0);
      setAbortController(null);
    }
  };

  const stopProcessing = () => {
    if (abortController) {
      addLog('Stopping processing...');
      abortController.abort();
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
              <h2>Connect to OpenAI-Compatible API</h2>
              <p>Use an OpenAI-compatible endpoint (Ollama, LM Studio, OpenAI) to rewrite files.</p>
            </div>

            <form className="poly-engine-login-form" onSubmit={handleLogin}>
              <div className="form-group">
                <label htmlFor="poly-url">API Base URL</label>
                <input
                  id="poly-url"
                  type="url"
                  placeholder="http://localhost:11434/v1"
                  value={apiBaseUrl}
                  onChange={(e) => setApiBaseUrl(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="poly-key">API Key (optional)</label>
                <input
                  id="poly-key"
                  type="password"
                  placeholder="Only required for hosted APIs"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
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

            <div className="mode-selection">
              <label className="mode-toggle">
                <input
                  type="checkbox"
                  checked={useToolCalling}
                  onChange={(e) => setUseToolCalling(e.target.checked)}
                />
                <span>Use intelligent editing mode (recommended for large files)</span>
              </label>
              <p className="mode-description">
                {useToolCalling 
                  ? "AI will make targeted edits using tools for more reliable results."
                  : "AI will rewrite the entire file in one go (may fail on large files)."}
              </p>
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
              {isProcessing && (
                <button
                  className="stop-btn"
                  onClick={stopProcessing}
                  title="Stop processing"
                >
                  Stop
                </button>
              )}
            </div>
          </div>

          <div className="poly-engine-logs">
            <h3>Processing Logs</h3>
            <div className="poly-engine-logs-container">
              {logs.length === 0 ? (
                <p className="poly-engine-logs-empty">No logs yet. Start processing a file to see logs here.</p>
              ) : (
                logs.map((log, index) => {
                  const getIcon = () => {
                    switch (log.type) {
                      case 'success':
                        return <FiCheck className="log-icon log-icon-success" />;
                      case 'error':
                        return <FiX className="log-icon log-icon-error" />;
                      case 'complete':
                        return <FiCheckCircle className="log-icon log-icon-complete" />;
                      default:
                        return null;
                    }
                  };

                  return (
                    <div key={index} className={`poly-engine-log-entry log-type-${log.type || 'info'}`}>
                      {getIcon()}
                      <span className="log-message">{log.message}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
