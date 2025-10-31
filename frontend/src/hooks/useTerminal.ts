import { useState, useRef, useEffect } from "react";
import { useWebSocket, Command } from "./useWebSocket";
import { useAuth } from "../contexts/AuthContext";

export interface TerminalTab {
  id: string;
  title: string;
  agent: any;
  history: any[];
}

export function useTerminal() {
  const [terminalTabs, setTerminalTabs] = useState<TerminalTab[]>([]);
  const [activeTerminalTab, setActiveTerminalTab] = useState<string | null>(null);
  const [isTerminalOpen, setIsTerminalOpen] = useState(false);
  const [terminalHeight, setTerminalHeight] = useState(300);
  const [isDragging, setIsDragging] = useState(false);
  const [currentCommand, setCurrentCommand] = useState("");
  const [loadingMoreHistory, setLoadingMoreHistory] = useState<{ [agentId: string]: boolean }>({});
  const [commandOffsets, setCommandOffsets] = useState<{ [agentId: string]: number }>({});
  const dragRef = useRef<HTMLDivElement>(null);
  
  // Get auth context for username
  const { user } = useAuth();
  
  // Get WebSocket functions
  const { sendCommand, getCommands, commands, commandTotalCounts, loadCommandHistory } = useWebSocket(true);

  const handleAgentClick = (agent: any) => {
    const existingTab = terminalTabs.find(tab => tab.agent.id === agent.id);
    
    if (existingTab) {
      setActiveTerminalTab(existingTab.id);
    } else {
      const newTab = {
        id: `tab-${Date.now()}`,
        title: agent.name,
        agent,
        history: []
      };
      setTerminalTabs(prev => [...prev, newTab]);
      setActiveTerminalTab(newTab.id);
      
      // Load initial 25 commands for this agent using GraphQL with pagination
      setCommandOffsets(prev => ({ ...prev, [agent.id]: 0 }));
      loadCommandHistory(agent.id, 25, 0);
    }
    
    setIsTerminalOpen(true);
  };

  const loadMoreHistory = (agentId: string) => {
    const currentOffset = commandOffsets[agentId] || 0;
    const loadedCount = (commands[agentId] || []).length;
    const totalCount = commandTotalCounts[agentId] || 0;
    
    // Check if there are more commands to load
    if (loadedCount >= totalCount) {
      return; // No more commands to load
    }
    
    // Check if already loading
    if (loadingMoreHistory[agentId]) {
      return;
    }
    
    setLoadingMoreHistory(prev => ({ ...prev, [agentId]: true }));
    
    const newOffset = currentOffset + 25;
    setCommandOffsets(prev => ({ ...prev, [agentId]: newOffset }));
    
    // Load next 25 commands
    loadCommandHistory(agentId, 25, newOffset);
    
    // Reset loading state after a short delay
    setTimeout(() => {
      setLoadingMoreHistory(prev => ({ ...prev, [agentId]: false }));
    }, 500);
  };

  const handleCommandSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentCommand.trim() || !activeTerminalTab) return;

    const activeTab = terminalTabs.find(tab => tab.id === activeTerminalTab);
    if (!activeTab) return;

    // Send command via WebSocket with username
    sendCommand(activeTab.agent.id, currentCommand, user?.username || 'reaper');

    // Add command to local history immediately
    const newEntry = {
      id: Date.now(),
      type: 'command',
      content: currentCommand,
      timestamp: new Date().toLocaleTimeString()
    };

    setTerminalTabs(prev => prev.map(tab => 
      tab.id === activeTerminalTab 
        ? { ...tab, history: [...tab.history, newEntry] }
        : tab
    ));

    setCurrentCommand("");
  };

  const closeTerminalTab = (tabId: string) => {
    const newTabs = terminalTabs.filter(tab => tab.id !== tabId);
    setTerminalTabs(newTabs);
    
    if (activeTerminalTab === tabId) {
      if (newTabs.length > 0) {
        setActiveTerminalTab(newTabs[newTabs.length - 1].id);
      } else {
        setActiveTerminalTab(null);
        setIsTerminalOpen(false);
      }
    }
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
  };

  const handleMouseMove = (e: MouseEvent) => {
    if (!isDragging) return;
    
    const newHeight = window.innerHeight - e.clientY;
    const maxHeight = window.innerHeight * 0.8; // Allow up to 80% of screen height
    setTerminalHeight(Math.max(60, Math.min(maxHeight, newHeight)));
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      
      return () => {
        document.removeEventListener('mousemove', handleMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isDragging]);

  // Sync commands from WebSocket to terminal history
  useEffect(() => {
    terminalTabs.forEach(tab => {
      const agentCommands = commands[tab.agent.id] || [];
      if (agentCommands.length > 0) {
        // Convert commands to terminal history format with user info
        const historyEntries = agentCommands.map((cmd: Command) => [
          {
            id: cmd.id,
            type: 'command',
            content: `[${cmd.clientUsername}] $ ${cmd.command}`,
            timestamp: new Date(cmd.createdAt).toLocaleTimeString(),
            username: cmd.clientUsername,
            isCommand: true
          },
          ...(cmd.output ? [{
            id: cmd.id + 0.1,
            type: 'response',
            content: cmd.output,
            timestamp: cmd.executedAt ? new Date(cmd.executedAt).toLocaleTimeString() : new Date(cmd.createdAt).toLocaleTimeString(),
            isCommand: false
          }] : [])
        ]).flat();

        // Update tab history if it's different
        setTerminalTabs(prev => prev.map(t => 
          t.id === tab.id 
            ? { ...t, history: historyEntries }
            : t
        ));
      }
    });
  }, [commands]);

  // Adjust main content margin when terminal is open to push content up
  useEffect(() => {
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
      if (isTerminalOpen) {
        mainContent.style.marginBottom = `${terminalHeight}px`;
      } else {
        mainContent.style.marginBottom = '0px';
      }
    }
  }, [isTerminalOpen, terminalHeight]);

  return {
    terminalTabs,
    activeTerminalTab,
    isTerminalOpen,
    terminalHeight,
    isDragging,
    currentCommand,
    setCurrentCommand,
    dragRef,
    handleAgentClick,
    handleCommandSubmit,
    closeTerminalTab,
    handleMouseDown,
    setActiveTerminalTab,
    loadMoreHistory,
    loadingMoreHistory,
    commandTotalCounts
  };
}
