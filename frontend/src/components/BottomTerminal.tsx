import { useRef, useEffect, useState } from "react";
import { FaTimes, FaSpinner, FaChevronUp } from "react-icons/fa";
import { GiScythe } from "react-icons/gi";
import FileUpload from "./FileUpload";
import "./FileUpload.css";

interface TerminalTab {
  id: string;
  title: string;
  agent: any;
  history: any[];
}

interface BottomTerminalProps {
  isTerminalOpen: boolean;
  terminalTabs: TerminalTab[];
  activeTerminalTab: string | null;
  terminalHeight: number;
  isDragging: boolean;
  currentCommand: string;
  setCurrentCommand: (command: string) => void;
  onCommandSubmit: (e: React.FormEvent) => void;
  onFileUpload?: (file: File, remotePath: string) => void;
  onCloseTab: (tabId: string) => void;
  onSetActiveTab: (tabId: string) => void;
  onMouseDown: (e: React.MouseEvent) => void;
  dragRef: React.RefObject<HTMLDivElement>;
  onLoadMoreHistory?: (agentId: string) => void;
  loadingMoreHistory?: { [agentId: string]: boolean };
  commandTotalCounts?: { [agentId: string]: number };
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

export default function BottomTerminal({
  isTerminalOpen,
  terminalTabs,
  activeTerminalTab,
  terminalHeight,
  isDragging,
  currentCommand,
  setCurrentCommand,
  onCommandSubmit,
  onFileUpload,
  onCloseTab,
  onSetActiveTab,
  onMouseDown,
  dragRef,
  onLoadMoreHistory,
  loadingMoreHistory,
  commandTotalCounts
}: BottomTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [userScrolled, setUserScrolled] = useState(false);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [inputBuffer, setInputBuffer] = useState<string>('');
  const [showFileUpload, setShowFileUpload] = useState(false);
  const [previousScrollHeight, setPreviousScrollHeight] = useState(0);
  const [previousScrollTop, setPreviousScrollTop] = useState(0);
  const [showLoadMoreButton, setShowLoadMoreButton] = useState(false);
  const activeTabData = terminalTabs.find(tab => tab.id === activeTerminalTab);

  // Auto-scroll terminal or maintain exact position when loading more history
  useEffect(() => {
    if (terminalRef.current) {
      const element = terminalRef.current;
      
      // If we were loading more history, maintain exact visual position
      if (previousScrollHeight > 0 && element.scrollHeight > previousScrollHeight) {
        // Calculate how much new content was added
        const scrollDifference = element.scrollHeight - previousScrollHeight;
        // Adjust scroll position to keep user at the same visual location
        element.scrollTop = previousScrollTop + scrollDifference;
        setPreviousScrollHeight(0); // Reset
        setPreviousScrollTop(0); // Reset
      } else if (!userScrolled) {
        // Normal auto-scroll behavior for new commands
        element.scrollTop = element.scrollHeight;
      }
    }
  }, [activeTabData?.history, userScrolled, previousScrollHeight, previousScrollTop]);

  // Track scroll position and show/hide load more button
  const handleScroll = () => {
    if (terminalRef.current) {
      const element = terminalRef.current;
      const isAtBottom = element.scrollTop + element.clientHeight >= element.scrollHeight - 10;
      setUserScrolled(!isAtBottom);
      
      // Show load more button if near top
      const isNearTop = element.scrollTop <= 150; // Within 150px of top
      const agentId = activeTabData?.agent?.id;
      
      if (agentId) {
        const loadedCount = activeTabData?.history?.length || 0;
        const totalCount = commandTotalCounts?.[agentId] || 0;
        const isLoading = loadingMoreHistory?.[agentId] || false;
        
        // Show button if near top, has more to load, and not currently loading
        setShowLoadMoreButton(isNearTop && loadedCount < totalCount && !isLoading);
      } else {
        setShowLoadMoreButton(false);
      }
    }
  };

  // Handle load more button click
  const handleLoadMoreClick = () => {
    if (!terminalRef.current || !activeTabData || !onLoadMoreHistory) return;
    
    const element = terminalRef.current;
    const agentId = activeTabData.agent?.id;
    
    if (!agentId) return;
    
    // Save current scroll state
    setPreviousScrollHeight(element.scrollHeight);
    setPreviousScrollTop(element.scrollTop);
    
    // Hide button and load more
    setShowLoadMoreButton(false);
    onLoadMoreHistory(agentId);
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


  if (!isTerminalOpen) return null;

  return (
    <div 
      className={`bottom-terminal ${isDragging ? 'dragging' : ''}`} 
      style={{ height: `${terminalHeight}px` }}
    >
      <div className="terminal-drag-handle"
           onMouseDown={onMouseDown}
           ref={dragRef}>
        <div className="drag-indicator"></div>
      </div>

      <div className="terminal-tabs">
        {terminalTabs.map((tab) => (
          <div
            key={tab.id}
            className={`terminal-tab ${activeTerminalTab === tab.id ? 'active' : ''}`}
            onClick={() => onSetActiveTab(tab.id)}
          >
            <span className="tab-title">{tab.title}</span>
            <button
              className="tab-close"
              onClick={(e) => {
                e.stopPropagation();
                onCloseTab(tab.id);
              }}
            >
              <FaTimes />
            </button>
          </div>
        ))}
      </div>

      <div 
        className="terminal-content" 
        ref={terminalRef} 
        onScroll={handleScroll}
      >
        {activeTabData && (
          <>
            {/* Load more button at top */}
            {showLoadMoreButton && !loadingMoreHistory?.[activeTabData.agent.id] && (
              <div className="terminal-load-more-container">
                <button className="terminal-load-more-button" onClick={handleLoadMoreClick}>
                  <FaChevronUp />
                  <span>
                    Load more ({activeTabData.history.length} of {commandTotalCounts?.[activeTabData.agent.id]})
                  </span>
                </button>
              </div>
            )}
            
            {/* Loading spinner at top */}
            {loadingMoreHistory?.[activeTabData.agent.id] && (
              <div className="terminal-loading-spinner">
                <FaSpinner className="spinner-icon" />
                <span>Loading more history...</span>
              </div>
            )}
            
            {activeTabData.history.map((entry) => (
              <div key={entry.id} className={`terminal-line ${entry.type}`}>
                <span className="terminal-timestamp">[{entry.timestamp}]</span>
                <span className="terminal-content-text">
                  {entry.type === 'command' ? `$ ${entry.content}` : filterLootData(entry.content)}
                </span>
              </div>
            ))}
          </>
        )}
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
            placeholder="Enter command..."
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
