import { useRef, useEffect, useState, useMemo } from "react";
import { GiScythe } from "react-icons/gi";
import { FaDollarSign } from "react-icons/fa";
import { GiOctopus } from "react-icons/gi";
import FileUpload from "./FileUpload";
import "./FileUpload.css";

interface TerminalEntry {
  id: number;
  type: 'command' | 'response';
  content: string;
  timestamp: string;
}

interface Agent {
  id: string;
  name: string;
  status: string;
  ip: string;
  os: string;
  lastSeen: string;
}

interface GlobalTerminalProps {
  terminalHistory: TerminalEntry[];
  currentCommand: string;
  setCurrentCommand: (command: string) => void;
  onCommandSubmit: (e: React.FormEvent) => void;
  onFileUpload?: (file: File, remotePath: string) => void;
  agents?: Agent[];
}

  // Function to filter out loot data from terminal output
  const filterLootData = (content: string): string => {
    // Filter out loot entries
    const lootIndex = content.indexOf('LOOT_ENTRIES:');
    if (lootIndex !== -1) {
      content = content.substring(0, lootIndex).trim();
    }
    
    return content;
  };

export default function GlobalTerminal({ 
  terminalHistory, 
  currentCommand, 
  setCurrentCommand, 
  onCommandSubmit,
  onFileUpload,
  agents
}: GlobalTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [userScrolled, setUserScrolled] = useState(false);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [inputBuffer, setInputBuffer] = useState<string>('');
  const [showFileUpload, setShowFileUpload] = useState(false);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current && !userScrolled) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalHistory, userScrolled]);

  // Track if user manually scrolled
  const handleScroll = () => {
    if (terminalRef.current) {
      const element = terminalRef.current;
      const isAtBottom = element.scrollTop + element.clientHeight >= element.scrollHeight - 10;
      setUserScrolled(!isAtBottom);
    }
  };

  // Handle command history navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        // Save current input to buffer if we're starting navigation
        if (historyIndex === -1 && currentCommand.trim()) {
          setInputBuffer(currentCommand);
        }
        
        // Navigate backwards through history (newest to oldest)
        const newIndex = historyIndex === -1 ? 0 : Math.min(historyIndex + 1, commandHistory.length - 1);
        setHistoryIndex(newIndex);
        setCurrentCommand(commandHistory[newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex !== -1) {
        const newIndex = historyIndex - 1;
        if (newIndex < 0) {
          // Go back to input buffer or empty
          setHistoryIndex(-1);
          setCurrentCommand(inputBuffer);
          setInputBuffer('');
        } else {
          setHistoryIndex(newIndex);
          setCurrentCommand(commandHistory[newIndex]);
        }
      }
    }
  };

  // Handle command submission with history
  const handleCommandSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (currentCommand.trim()) {
      // Add to history (max 50 commands) - newest first
      const newHistory = [currentCommand.trim(), ...commandHistory].slice(0, 50);
      setCommandHistory(newHistory);
      setHistoryIndex(-1);
      setInputBuffer(''); // Clear buffer after submission
      onCommandSubmit(e);
    }
  };

  // Handle file upload
  const handleFileUpload = async (file: File, remotePath: string) => {
    if (!onFileUpload) return;
    
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
        reader.readAsDataURL(file);
      });

      // Create the put command
      const putCommand = `put "${remotePath}" "${base64}"`;
      setCurrentCommand(putCommand);
      
      // Submit the command
      const fakeEvent = {
        preventDefault: () => {},
      } as React.FormEvent;
      
      setCurrentCommand(putCommand);
      onCommandSubmit(fakeEvent);
    } catch (error) {
      console.error('Failed to process file for upload:', error);
    }
  };


  // Calculate total agents
  const totalAgents = useMemo(() => {
    return agents?.length || 0;
  }, [agents]);

  return (
    <div className="fullscreen-terminal">
      {/* Octopus background icon */}
      <div className="octopus-background">
        <GiOctopus className="octopus-icon" />
      </div>
      
      <div className="agents-search">
        <div className="search-input-container">
        </div>
        <div className="agent-stats">
          <FaDollarSign className="stats-icon" />
          <span className="stats-text">
            {totalAgents} {totalAgents === 1 ? 'agent' : 'agents'}
          </span>
        </div>
      </div>
      <div 
        className="terminal-content" 
        ref={terminalRef} 
        onScroll={handleScroll}
      >
        {terminalHistory.map((entry) => (
          <div key={entry.id} className={`terminal-line ${entry.type}`}>
            <span className="terminal-timestamp">[{entry.timestamp}]</span>
            <span className="terminal-content-text">
              {entry.type === 'command' ? `$ ${entry.content}` : filterLootData(entry.content)}
            </span>
          </div>
        ))}
      </div>

      <form className="terminal-input-form" onSubmit={handleCommandSubmit}>
        <div className="terminal-prompt">
          <span className="prompt-symbol">$</span>
          <input
            ref={inputRef}
            type="text"
            value={currentCommand}
            onChange={(e) => setCurrentCommand(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter global command..."
            className="terminal-input"
            autoFocus
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        <button type="submit" className="terminal-send">
          <GiScythe />
          <span>REAP</span>
        </button>
      </form>

      <FileUpload
        isVisible={showFileUpload}
        onFileSelect={handleFileUpload}
        onClose={() => setShowFileUpload(false)}
      />
    </div>
  );
}
