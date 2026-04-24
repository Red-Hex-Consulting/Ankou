import { useWebSocket } from "../hooks/useWebSocket";
import { useAuth } from "../contexts/AuthContext";
import { FaThumbsUp, FaExclamationTriangle, FaSearch, FaDollarSign, FaQuestion, FaBolt, FaUser, FaWindows, FaLinux, FaApple, FaClock, FaHistory, FaUpload, FaSyringe, FaCamera, FaCog, FaTerminal, FaTrashAlt } from "react-icons/fa";
import { useState, useMemo, useRef } from "react";
import { ContextMenu, ContextMenuItem } from "./ContextMenu";
import FileUploadModal from "./FileUploadModal";
import ShellcodeInjectModal from "./ShellcodeInjectModal";
import RemoveAgentModal from "./RemoveAgentModal";
import { getScripts } from "./Scripts";
import "./ContextMenu.css";
import "./FileUploadModal.css";
import "./ShellcodeInjectModal.css";
import "./RemoveAgentModal.css";

interface Agent {
  id: string;
  name: string;
  status: string;
  ip: string;
  lastSeen: string;
  os: string;
  handlerName?: string;
  reconnectInterval?: number;
  privileges?: string;
}

interface AgentsTableProps {
  onAgentClick: (agent: Agent) => void;
  onAgentPut?: (agent: Agent) => void;
  onAgentInject?: (agent: Agent) => void;
  isActive: boolean;
}

export default function AgentsTable({ onAgentClick, onAgentPut, onAgentInject, isActive }: AgentsTableProps) {
  const { agents, handlers, sendCommand, sendMessage } = useWebSocket(isActive);
  const { user } = useAuth();
  const [searchTerm, setSearchTerm] = useState("");
  const [timeFormat, setTimeFormat] = useState<'relative' | 'timestamp'>('timestamp');
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; agent: Agent } | null>(null);
  const [showFileDialog, setShowFileDialog] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showInjectModal, setShowInjectModal] = useState(false);
  const [showRemoveModal, setShowRemoveModal] = useState(false);
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

  const formatLastSeenRelative = (lastSeen: string) => {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins} min ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const formatLastSeenTimestamp = (lastSeen: string) => {
    const date = new Date(lastSeen);
    
    // Format: "Dec 26, 3:45 PM"
    const month = date.toLocaleString('en-US', { month: 'short' });
    const day = date.getDate();
    const time = date.toLocaleString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit',
      hour12: true 
    });
    
    return `${month} ${day}, ${time}`;
  };

  const formatLastSeenTooltip = (lastSeen: string) => {
    const date = new Date(lastSeen);
    // Full format for tooltip: "December 26, 2025, 3:45:30 PM"
    return date.toLocaleString('en-US', { 
      month: 'long',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    });
  };

  const formatLastSeen = (lastSeen: string) => {
    return timeFormat === 'relative' 
      ? formatLastSeenRelative(lastSeen) 
      : formatLastSeenTimestamp(lastSeen);
  };

  const getOSIcon = (os: string) => {
    const osLower = os.toLowerCase();

    if (osLower.includes('windows')) {
      return <FaWindows style={{ color: '#ffffff' }} title={os} />;
    } else if (osLower.includes('linux')) {
      return <FaLinux style={{ color: '#ffffff' }} title={os} />;
    } else if (osLower.includes('darwin') || osLower.includes('mac')) {
      return <FaApple style={{ color: '#ffffff' }} title={os} />;
    } else {
      return <FaQuestion style={{ color: 'var(--text-secondary)' }} title={os || 'Unknown OS'} />;
    }
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
    setContextMenu({ x: e.clientX, y: e.clientY, agent });
  };

  const closeContextMenu = () => setContextMenu(null);

  const handleContextMenuPut = () => {
    if (contextMenu?.agent) {
      setSelectedAgent(contextMenu.agent);
      setShowFileDialog(true);
      if (fileInputRef.current) {
        fileInputRef.current.click();
      }
    }
    closeContextMenu();
  };

  const handleContextMenuInject = () => {
    if (contextMenu?.agent) {
      setSelectedAgent(contextMenu.agent);
      if (shellcodeInputRef.current) {
        shellcodeInputRef.current.click();
      }
    }
    closeContextMenu();
  };

  const handleContextMenuScreenshot = () => {
    if (!contextMenu?.agent || !sendCommand) return;
    const username = user?.username || 'operator';
    sendCommand(contextMenu.agent.id, 'screenshot', username);
    closeContextMenu();
  };

  const handleScriptExecute = (script: { id: string; name: string; commands: string[]; createdAt: string }) => {
    if (!contextMenu?.agent || !sendCommand) return;
    const agent = contextMenu.agent;
    const username = user?.username || 'operator';
    script.commands.forEach((command) => {
      sendCommand(agent.id, command, `${username} (script: ${script.name})`);
    });
    closeContextMenu();
  };

  const handleContextMenuRemove = () => {
    if (contextMenu?.agent) {
      setSelectedAgent(contextMenu.agent);
      setShowRemoveModal(true);
    }
    closeContextMenu();
  };

  const handleRemoveConfirm = () => {
    if (!selectedAgent || !sendMessage) return;

    sendMessage({
      type: 'remove_agent',
      agentId: selectedAgent.id
    });

    setShowRemoveModal(false);
    setSelectedAgent(null);
  };

  const handleRemoveCancel = () => {
    setShowRemoveModal(false);
    setSelectedAgent(null);
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
            <th>ID</th>
            <th>Agent</th>
            <th>Status</th>
            <th>IP</th>
            <th>OS</th>
            <th>Priv</th>
            <th>Interval</th>
            <th>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                <span>Seen</span>
                {timeFormat === 'timestamp' ? (
                  <FaClock 
                    onClick={(e) => {
                      e.stopPropagation();
                      setTimeFormat('relative');
                    }}
                    style={{ 
                      cursor: 'pointer', 
                      fontSize: '11px',
                      opacity: 0.6,
                      transition: 'opacity 0.2s'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
                    onMouseLeave={(e) => e.currentTarget.style.opacity = '0.6'}
                    title="Switch to relative time"
                  />
                ) : (
                  <FaHistory 
                    onClick={(e) => {
                      e.stopPropagation();
                      setTimeFormat('timestamp');
                    }}
                    style={{ 
                      cursor: 'pointer', 
                      fontSize: '11px',
                      opacity: 0.6,
                      transition: 'opacity 0.2s'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
                    onMouseLeave={(e) => e.currentTarget.style.opacity = '0.6'}
                    title="Switch to timestamp"
                  />
                )}
              </div>
            </th>
          </tr>
        </thead>
        <tbody>
          {filteredAgents && filteredAgents.map((agent) => (
            <tr
              key={agent.id}
              className={`agent-row ${contextMenu && contextMenu.agent?.id === agent.id ? 'context-menu-active' : ''}`}
              onClick={() => onAgentClick(agent)}
              onContextMenu={(e) => handleAgentRightClick(e, agent)}
            >
              <td className="agent-name" title={agent.name || ''}>
                {agent.name ? (
                  <span style={{ 
                    overflow: 'hidden', 
                    textOverflow: 'ellipsis', 
                    whiteSpace: 'nowrap',
                    display: 'block',
                    maxWidth: '150px'
                  }}>
                    {agent.name}
                  </span>
                ) : (
                  <FaQuestion style={{ color: 'var(--text-secondary)' }} />
                )}
              </td>
              <td className="agent-type" title={agent.handlerName || ''}>
                {agent.handlerName ? (
                  <span style={{ 
                    overflow: 'hidden', 
                    textOverflow: 'ellipsis', 
                    whiteSpace: 'nowrap',
                    display: 'block'
                  }}>
                    {agent.handlerName}
                  </span>
                ) : (
                  <FaQuestion style={{ color: 'var(--text-secondary)' }} />
                )}
              </td>
              <td title={calculateStatus(agent.lastSeen, agent.reconnectInterval)}>
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
              <td className="agent-ip" title={agent.ip || ''}>
                {agent.ip ? (
                  <span style={{ 
                    overflow: 'hidden', 
                    textOverflow: 'ellipsis', 
                    whiteSpace: 'nowrap',
                    display: 'block'
                  }}>
                    {agent.ip}
                  </span>
                ) : (
                  <FaQuestion style={{ color: 'var(--text-secondary)' }} />
                )}
              </td>
              <td className="agent-os">{agent.os ? getOSIcon(agent.os) : <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
              <td className="agent-priv">
                {(() => {
                  if (!agent.privileges) return null;
                  try {
                    const priv = JSON.parse(agent.privileges);
                    const hasAnyPrivilege = priv.isRoot || priv.isAdmin;
                    
                    return (
                      <span className="priv-indicators">
                        {priv.isRoot && (
                          <FaBolt 
                            style={{ 
                              color: '#ff4444',
                              marginRight: '4px',
                              filter: 'drop-shadow(0 0 3px #ff4444) drop-shadow(0 0 6px #ff0000)'
                            }} 
                            title={agent.os.toLowerCase().includes('windows') ? 'Elevated' : 'Root'}
                          />
                        )}
                        {priv.isAdmin && (
                          <FaBolt 
                            style={{ 
                              color: '#ffd700',
                              marginRight: priv.isRoot ? '0' : '4px',
                              filter: 'drop-shadow(0 0 3px #ffd700) drop-shadow(0 0 6px #ffaa00)'
                            }} 
                            title='Admin Group'
                          />
                        )}
                        {!hasAnyPrivilege && (
                          <FaUser
                            style={{ color: 'var(--success-green)' }}
                            title='Standard User'
                          />
                        )}
                      </span>
                    );
                  } catch {
                    return null;
                  }
                })()}
              </td>
              <td className="agent-callback" title={agent.reconnectInterval !== undefined && agent.reconnectInterval > 0 ? `${agent.reconnectInterval} seconds` : ''}>
                {agent.reconnectInterval !== undefined && agent.reconnectInterval > 0 ? (
                  <span style={{ 
                    overflow: 'hidden', 
                    textOverflow: 'ellipsis', 
                    whiteSpace: 'nowrap',
                    display: 'block'
                  }}>
                    {`${agent.reconnectInterval}s`}
                  </span>
                ) : (
                  <FaQuestion style={{ color: 'var(--text-secondary)' }} />
                )}
              </td>
              <td className="agent-lastseen" title={agent.lastSeen ? formatLastSeenTooltip(agent.lastSeen) : ''}>
                {agent.lastSeen ? (
                  <span style={{ 
                    overflow: 'hidden', 
                    textOverflow: 'ellipsis', 
                    whiteSpace: 'nowrap',
                    display: 'block'
                  }}>
                    {formatLastSeen(agent.lastSeen)}
                  </span>
                ) : (
                  <FaQuestion style={{ color: 'var(--text-secondary)' }} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {contextMenu && (() => {
        const agent = contextMenu.agent;
        const handler = handlers?.find(h => h.agentName === agent.handlerName);
        const canInject = handler?.supportedCommands.includes('injectsc') ?? false;
        const canScreenshot = handler?.supportedCommands.includes('screenshot') ?? false;
        const scripts = getScripts();

        return (
          <ContextMenu x={contextMenu.x} y={contextMenu.y} onClose={closeContextMenu}>
            <ContextMenuItem icon={<FaUpload />} label="Put File" onClick={handleContextMenuPut} />
            {canInject && (
              <ContextMenuItem icon={<FaSyringe />} label="Inject" onClick={handleContextMenuInject} />
            )}
            {canScreenshot && (
              <ContextMenuItem icon={<FaCamera />} label="Screenshot" onClick={handleContextMenuScreenshot} />
            )}
            <ContextMenuItem divider label="" onClick={() => {}} />
            {scripts.map((script) => (
              <ContextMenuItem
                key={script.id}
                icon={<FaTerminal />}
                label={script.name}
                onClick={() => handleScriptExecute(script)}
              />
            ))}
            {scripts.length === 0 && (
              <ContextMenuItem icon={<FaCog />} label="No scripts" onClick={() => {}} disabled />
            )}
            <ContextMenuItem divider label="" onClick={() => {}} />
            <ContextMenuItem icon={<FaTrashAlt />} label="Remove Agent" onClick={handleContextMenuRemove} danger />
          </ContextMenu>
        );
      })()}

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

      {/* Remove agent confirmation modal */}
      <RemoveAgentModal
        isVisible={showRemoveModal}
        agentName={selectedAgent?.name || ''}
        agentId={selectedAgent?.id || ''}
        onConfirm={handleRemoveConfirm}
        onCancel={handleRemoveCancel}
      />
    </div>
  );
}
