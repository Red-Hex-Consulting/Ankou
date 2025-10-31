import { useWebSocket } from "../hooks/useWebSocket";
import { useAuth } from "../contexts/AuthContext";
import { FaThumbsUp, FaExclamationTriangle, FaSearch, FaDollarSign, FaQuestion } from "react-icons/fa";
import { useState, useMemo, useRef } from "react";
import ContextMenu from "./ContextMenu";
import FileUploadModal from "./FileUploadModal";
import ShellcodeInjectModal from "./ShellcodeInjectModal";
import "./ContextMenu.css";
import "./FileUploadModal.css";
import "./ShellcodeInjectModal.css";

interface Agent {
  id: string;
  name: string;
  status: string;
  ip: string;
  lastSeen: string;
  os: string;
  handlerName?: string;
  reconnectInterval?: number;
}

interface AgentsTableProps {
  onAgentClick: (agent: Agent) => void;
  onAgentPut?: (agent: Agent) => void;
  onAgentInject?: (agent: Agent) => void;
  isActive: boolean;
}

export default function AgentsTable({ onAgentClick, onAgentPut, onAgentInject, isActive }: AgentsTableProps) {
  const { agents, sendCommand } = useWebSocket(isActive);
  const { user } = useAuth();
  const [searchTerm, setSearchTerm] = useState("");
  const [contextMenu, setContextMenu] = useState<{ visible: boolean; x: number; y: number; agent: Agent | null }>({
    visible: false,
    x: 0,
    y: 0,
    agent: null
  });
  const [showFileDialog, setShowFileDialog] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showInjectModal, setShowInjectModal] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedShellcodeFile, setSelectedShellcodeFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const shellcodeInputRef = useRef<HTMLInputElement>(null);

  // Calculate agent status based on last_seen and reconnect_interval
  const calculateStatus = (lastSeen: string, reconnectInterval?: number): string => {
    if (!reconnectInterval || reconnectInterval === 0) {
      return "online"; // Unknown interval - always online
    }

    const lastSeenDate = new Date(lastSeen);
    const now = new Date();
    const diffSeconds = (now.getTime() - lastSeenDate.getTime()) / 1000;
    
    // 200% grace period - very forgiving for network delays and processing time
    const graceMultiplier = 3; // 3x the interval before marking late
    const expectedCheckIn = reconnectInterval * graceMultiplier;
    
    return diffSeconds > expectedCheckIn ? "late" : "online";
  };

  const formatLastSeen = (lastSeen: string) => {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins} minutes ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hours ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} days ago`;
  };

  const filteredAgents = useMemo(() => {
    if (!agents || !searchTerm) return agents;
    
    return agents.filter(agent => 
      agent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.os.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.status.toLowerCase().includes(searchTerm.toLowerCase()) ||
      formatLastSeen(agent.lastSeen).toLowerCase().includes(searchTerm.toLowerCase()) ||
      (agent.handlerName ? agent.handlerName.toLowerCase().includes(searchTerm.toLowerCase()) : false)
    );
  }, [agents, searchTerm]);

  // Calculate total agents
  const totalAgents = useMemo(() => {
    return agents?.length || 0;
  }, [agents]);

  // Handle right-click for context menu
  const handleAgentRightClick = (e: React.MouseEvent, agent: Agent) => {
    e.preventDefault();
    e.stopPropagation();
    setContextMenu({
      visible: true,
      x: e.clientX,
      y: e.clientY,
      agent: agent
    });
  };

  // Handle context menu actions
  const handleContextMenuClose = () => {
    setContextMenu({ visible: false, x: 0, y: 0, agent: null });
  };

  const handleContextMenuPut = () => {
    if (contextMenu.agent) {
      setSelectedAgent(contextMenu.agent);
      setShowFileDialog(true);
      // Trigger file input
      if (fileInputRef.current) {
        fileInputRef.current.click();
      }
    }
    setContextMenu({ visible: false, x: 0, y: 0, agent: null });
  };

  const handleContextMenuInject = () => {
    if (contextMenu.agent) {
      setSelectedAgent(contextMenu.agent);
      // Trigger shellcode file input
      if (shellcodeInputRef.current) {
        shellcodeInputRef.current.click();
      }
    }
    setContextMenu({ visible: false, x: 0, y: 0, agent: null });
  };

  const handleScriptExecute = (script: { id: string; name: string; commands: string[]; createdAt: string }) => {
    if (!contextMenu.agent || !sendCommand) return;

    const agent = contextMenu.agent;
    const username = user?.username || 'operator';
    
    // Queue all commands in order
    script.commands.forEach((command) => {
      sendCommand(agent.id, command, `${username} (script: ${script.name})`);
    });
    
    setContextMenu({ visible: false, x: 0, y: 0, agent: null });
  };

  // Handle file selection
  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || !selectedAgent) return;

    setSelectedFile(file);
    setShowUploadModal(true);
  };

  // Handle upload confirmation
  const handleUploadConfirm = async (remotePath: string) => {
    if (!selectedFile || !selectedAgent) return;

    try {
      // Read file as ArrayBuffer and convert to hex
      const fileHex = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          try {
            const arrayBuffer = reader.result as ArrayBuffer;
            if (!arrayBuffer) {
              reject(new Error('Invalid file data'));
              return;
            }
            
            // Convert ArrayBuffer to hex string
            const bytes = new Uint8Array(arrayBuffer);
            const hex = Array.from(bytes)
              .map(byte => byte.toString(16).padStart(2, '0'))
              .join('');
            
            resolve(hex);
          } catch (err) {
            reject(err);
          }
        };
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsArrayBuffer(selectedFile);
      });

      // Validate file hex
      if (!fileHex || fileHex.length === 0) {
        throw new Error('Empty file hex');
      }

      // Create the put command with proper escaping
      const escapedHex = fileHex.replace(/"/g, '\\"');
      const putCommand = `put "${remotePath}" "${escapedHex}"`;
      
      // Send command to the specific agent
      if (sendCommand) {
        const username = user?.username || 'operator';
        sendCommand(selectedAgent.id, putCommand, username);
      }

      // Reset state
      setShowUploadModal(false);
      setShowFileDialog(false);
      setSelectedAgent(null);
      setSelectedFile(null);
      
      // Clear the file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

    } catch (error) {
      console.error('Failed to process file for upload:', error);
      alert(`Failed to process file for upload: ${error instanceof Error ? error.message : 'Unknown error'}`);
      setShowUploadModal(false);
      setShowFileDialog(false);
      setSelectedAgent(null);
      setSelectedFile(null);
    }
  };

  // Handle upload cancellation
  const handleUploadCancel = () => {
    setShowUploadModal(false);
    setShowFileDialog(false);
    setSelectedAgent(null);
    setSelectedFile(null);
    
    // Clear the file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Handle shellcode file selection
  const handleShellcodeFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || !selectedAgent) return;

    setSelectedShellcodeFile(file);
    setShowInjectModal(true);
  };

  // Handle shellcode injection confirmation
  const handleInjectConfirm = async () => {
    if (!selectedShellcodeFile || !selectedAgent) return;

    try {
      // Read file as ArrayBuffer and convert to hex
      const shellcodeHex = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          try {
            const arrayBuffer = reader.result as ArrayBuffer;
            if (!arrayBuffer) {
              reject(new Error('Invalid file data'));
              return;
            }
            
            // Convert ArrayBuffer to hex string
            const bytes = new Uint8Array(arrayBuffer);
            const hex = Array.from(bytes)
              .map(byte => byte.toString(16).padStart(2, '0'))
              .join('');
            
            resolve(hex);
          } catch (err) {
            reject(err);
          }
        };
        reader.onerror = () => reject(new Error('Failed to read shellcode file'));
        reader.readAsArrayBuffer(selectedShellcodeFile);
      });

      // Validate shellcode hex
      if (!shellcodeHex || shellcodeHex.length === 0) {
        throw new Error('Empty shellcode hex');
      }

      // Create the injectsc command
      const injectCommand = `injectsc "${shellcodeHex}"`;
      
      // Send command to the specific agent
      if (sendCommand) {
        const username = user?.username || 'operator';
        sendCommand(selectedAgent.id, injectCommand, username);
      }

      // Reset state
      setShowInjectModal(false);
      setSelectedAgent(null);
      setSelectedShellcodeFile(null);
      
      // Clear the file input
      if (shellcodeInputRef.current) {
        shellcodeInputRef.current.value = '';
      }

    } catch (error) {
      console.error('Failed to process shellcode for injection:', error);
      alert(`Failed to process shellcode for injection: ${error instanceof Error ? error.message : 'Unknown error'}`);
      setShowInjectModal(false);
      setSelectedAgent(null);
      setSelectedShellcodeFile(null);
    }
  };

  // Handle injection cancellation
  const handleInjectCancel = () => {
    setShowInjectModal(false);
    setSelectedAgent(null);
    setSelectedShellcodeFile(null);
    
    // Clear the file input
    if (shellcodeInputRef.current) {
      shellcodeInputRef.current.value = '';
    }
  };

  return (
    <div className="agents-container">
      <div className="agents-search">
        <div className="search-input-container">
          <FaSearch className="search-icon" />
          <input
            type="text"
            placeholder="Search agents..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
        
        <div className="agent-stats">
          <FaDollarSign className="stats-icon" />
          <span className="stats-text">
            {totalAgents} {totalAgents === 1 ? 'agent' : 'agents'}
          </span>
        </div>
      </div>
      
      <table className="agents-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Agent Type</th>
            <th>Status</th>
            <th>IP</th>
            <th>OS</th>
            <th>Callback Interval</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {filteredAgents && filteredAgents.map((agent) => (
            <tr 
              key={agent.id}
              className="agent-row"
              onClick={() => onAgentClick(agent)}
              onContextMenu={(e) => handleAgentRightClick(e, agent)}
            >
              <td className="agent-name">{agent.name || <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
              <td className="agent-type">
                {agent.handlerName ? agent.handlerName : <FaQuestion style={{ color: 'var(--text-secondary)' }} />}
              </td>
              <td>
                {(() => {
                  const status = calculateStatus(agent.lastSeen, agent.reconnectInterval);
                  return (
                    <span className={`status-badge ${status.toLowerCase()}`}>
                      {status === "late" ? (
                        <>
                          <FaExclamationTriangle className="status-icon" />
                          late
                        </>
                      ) : (
                        <>
                          <FaThumbsUp className="status-icon" />
                          {status}
                        </>
                      )}
                    </span>
                  );
                })()}
              </td>
              <td className="agent-ip">{agent.ip || <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
              <td className="agent-os">{agent.os || <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
              <td className="agent-callback">
                {agent.reconnectInterval !== undefined && agent.reconnectInterval > 0 
                  ? `${agent.reconnectInterval}s` 
                  : <FaQuestion style={{ color: 'var(--text-secondary)' }} />
                }
              </td>
              <td className="agent-lastseen">{agent.lastSeen ? formatLastSeen(agent.lastSeen) : <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <ContextMenu
        isVisible={contextMenu.visible}
        x={contextMenu.x}
        y={contextMenu.y}
        onClose={handleContextMenuClose}
        onPut={handleContextMenuPut}
        onInject={handleContextMenuInject}
        onScriptExecute={handleScriptExecute}
      />

      {/* Hidden file input for file uploads */}
      <input
        ref={fileInputRef}
        type="file"
        onChange={handleFileSelect}
        style={{ display: 'none' }}
        accept="*/*"
      />

      {/* Hidden file input for shellcode injection */}
      <input
        ref={shellcodeInputRef}
        type="file"
        onChange={handleShellcodeFileSelect}
        style={{ display: 'none' }}
        accept=".bin,.shellcode,.raw,*"
      />

      {/* File upload confirmation modal */}
      <FileUploadModal
        isVisible={showUploadModal}
        fileName={selectedFile?.name || ''}
        agentName={selectedAgent?.name || ''}
        onConfirm={handleUploadConfirm}
        onCancel={handleUploadCancel}
      />

      {/* Shellcode injection confirmation modal */}
      <ShellcodeInjectModal
        isVisible={showInjectModal}
        fileName={selectedShellcodeFile?.name || ''}
        agentName={selectedAgent?.name || ''}
        onConfirm={handleInjectConfirm}
        onCancel={handleInjectCancel}
      />
    </div>
  );
}
