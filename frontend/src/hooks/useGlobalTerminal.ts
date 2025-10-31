import { useState, useRef, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";

export interface TerminalEntry {
  id: number;
  type: 'command' | 'response';
  content: string;
  timestamp: string;
}

interface GlobalTerminalProps {
  ws?: WebSocket | null;
  isConnected?: boolean;
}

export function useGlobalTerminal({ ws, isConnected }: GlobalTerminalProps = {}) {
  const { user } = useAuth();
  const [globalTerminalHistory, setGlobalTerminalHistory] = useState<TerminalEntry[]>([]);
  const [globalCurrentCommand, setGlobalCurrentCommand] = useState("");
  const globalTerminalRef = useRef<HTMLDivElement>(null);

  const handleGlobalCommandSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!globalCurrentCommand.trim()) return;

    const timestamp = new Date().toLocaleTimeString();
    const commandEntry = {
      id: Date.now(),
      type: 'command' as const,
      content: globalCurrentCommand,
      timestamp
    };

    // Add command to global terminal history
    setGlobalTerminalHistory(prev => [...prev, commandEntry]);

    // Send global command via WebSocket
    if (ws && isConnected) {
      const message = {
        type: "global_command",
        command: globalCurrentCommand.trim(),
        username: user?.username || "operator"
      };
      
      ws.send(JSON.stringify(message));
      
      // Add immediate confirmation
      const confirmationEntry = {
        id: Date.now() + 1,
        type: 'response' as const,
        content: `Global command queued: ${globalCurrentCommand}`,
        timestamp: new Date().toLocaleTimeString()
      };
      
      setGlobalTerminalHistory(prev => [...prev, confirmationEntry]);
    } else {
      // Fallback if WebSocket not connected
      const errorEntry = {
        id: Date.now() + 1,
        type: 'response' as const,
        content: "Error: Not connected to server",
        timestamp: new Date().toLocaleTimeString()
      };
      
      setGlobalTerminalHistory(prev => [...prev, errorEntry]);
    }

    setGlobalCurrentCommand("");
  };

  // Handle WebSocket messages for global commands
  useEffect(() => {
    if (!ws) return;

    const handleMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.type === "global_command_queued") {
          const responseEntry = {
            id: Date.now(),
            type: 'response' as const,
            content: `Global command sent to ${data.agentCount} agents: ${data.command}`,
            timestamp: new Date().toLocaleTimeString()
          };
          
          setGlobalTerminalHistory(prev => [...prev, responseEntry]);
        }
      } catch (error) {
        console.error("Error parsing WebSocket message:", error);
      }
    };

    ws.addEventListener('message', handleMessage);
    return () => ws.removeEventListener('message', handleMessage);
  }, [ws]);

  // Auto-scroll global terminal
  useEffect(() => {
    if (globalTerminalRef.current) {
      globalTerminalRef.current.scrollTop = globalTerminalRef.current.scrollHeight;
    }
  }, [globalTerminalHistory]);

  return {
    globalTerminalHistory,
    globalCurrentCommand,
    setGlobalCurrentCommand,
    globalTerminalRef,
    handleGlobalCommandSubmit
  };
}
