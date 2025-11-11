import { useState, useEffect } from 'react';
import { useServerUrl } from '../contexts/ServerContext';

export interface Agent {
  id: string;
  name: string;
  status: string;
  ip: string;
  lastSeen: string;
  os: string;
  createdAt: string;
  handlerId?: string;
  handlerName?: string;
  reconnectInterval?: number;
}

export interface Command {
  id: number;
  agentId: string;
  command: string;
  clientUsername: string;
  status: string;
  output: string;
  createdAt: string;
  executedAt?: string;
}

export interface Listener {
  id: string;
  name: string;
  type: string;
  endpoint: string;
  status: string;
  description?: string;
  createdAt: string;
}

export interface AgentHandler {
  id: string;
  agentName: string;
  agentHttpHeaderId: string;
  supportedCommands: string[];
}

// Global WebSocket singleton - only ONE connection for the entire app
class WebSocketManager {
  private static instance: WebSocketManager;
  private ws: WebSocket | null = null;
  private isConnected = false;
  private agents: Agent[] = [];
  private commands: { [agentId: string]: Command[] } = {};
  private commandTotalCounts: { [agentId: string]: number } = {}; // Track total command counts
  private users: any[] = [];
  private observers: Set<() => void> = new Set();
  private listeners: Listener[] = [];
  private handlers: AgentHandler[] = [];
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;

  static getInstance(): WebSocketManager {
    if (!WebSocketManager.instance) {
      WebSocketManager.instance = new WebSocketManager();
    }
    return WebSocketManager.instance;
  }

  connect(serverUrl: string) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return; // Already connected
    }

    if (this.ws) {
      this.ws.close();
    }

    try {
      // Convert https:// to wss:// for WebSocket
      const wsUrl = serverUrl.replace('https://', 'wss://').replace('http://', 'ws://') + '/ws';
      this.ws = new WebSocket(wsUrl);
      
      this.ws.onopen = () => {
        this.isConnected = true;
        this.notifyListeners();
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'agents') {
            this.agents = data.data;
            this.notifyListeners();
          } else if (data.type === 'users') {
            this.users = data.data;
            this.notifyListeners();
          } else if (data.type === 'listeners') {
            this.listeners = data.data;
            this.notifyListeners();
          } else if (data.type === 'handlers') {
            this.handlers = data.data;
            this.notifyListeners();
          } else if (data.type === 'commands_update') {
            this.commands = {
              ...this.commands,
              [data.agentId]: data.data
            };
            this.notifyListeners();
          } else if (data.type === 'commands') {
            this.commands = {
              ...this.commands,
              [data.agentId]: data.data
            };
            this.notifyListeners();
          } else if (data.type === 'loot_response') {
            const customEvent = new CustomEvent('loot-response', { detail: data });
            window.dispatchEvent(customEvent);
          } else if (data.type === 'loot_file_response') {
            const customEvent = new CustomEvent('loot-file-response', { detail: data });
            window.dispatchEvent(customEvent);
          } else if (data.type === 'graphql_response') {
            if (data.data && data.data.agents) {
              this.agents = data.data.agents;
              this.notifyListeners();
            }
            if (data.data && data.data.users) {
              this.users = data.data.users;
              this.notifyListeners();
            }
            if (data.data && data.data.listeners) {
              this.listeners = data.data.listeners;
              this.notifyListeners();
            }
            if (data.data && data.data.agentHandlers) {
              this.handlers = data.data.agentHandlers;
              this.notifyListeners();
            }
            if (data.data && data.data.commands) {
              const agentId = data.agentId;
              if (agentId) {
                // Handle paginated response
                if (data.isPaginated && data.offset > 0) {
                  // Prepend older commands to existing array
                  const existingCommands = this.commands[agentId] || [];
                  this.commands = {
                    ...this.commands,
                    [agentId]: [...data.data.commands, ...existingCommands]
                  };
                } else {
                  // Initial load or refresh
                  this.commands = {
                    ...this.commands,
                    [agentId]: data.data.commands
                  };
                }
                
                // Store total count if provided
                if (data.totalCount !== undefined) {
                  this.commandTotalCounts[agentId] = data.totalCount;
                }
                
                this.notifyListeners();
              }
            }
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this.notifyListeners();
        
        // Auto-reconnect
        this.reconnectTimeout = setTimeout(() => {
          this.connect(serverUrl);
        }, 3000);
      };

      this.ws.onerror = (error) => {
        console.error('Global WebSocket error:', error);
        this.isConnected = false;
        this.notifyListeners();
      };

    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      this.isConnected = false;
      this.notifyListeners();
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.isConnected = false;
    this.notifyListeners();
  }

  private notifyListeners() {
    this.observers.forEach(listener => listener());
  }

  addListener(listener: () => void) {
    this.observers.add(listener);
  }

  removeListener(listener: () => void) {
    this.observers.delete(listener);
  }

  getState() {
    return {
      isConnected: this.isConnected,
      agents: this.agents,
      commands: this.commands,
      commandTotalCounts: this.commandTotalCounts,
      users: this.users,
      listeners: this.listeners,
      handlers: this.handlers
    };
  }

  getWebSocket() {
    return this.ws;
  }

  sendCommand(agentId: string, command: string, username: string = 'reaper') {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'submit_command',
        agentId,
        command,
        username
      }));
    }
  }

  getCommands(agentId: string) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      const query = `
        query {
          commands(agentId: "${agentId}") {
            id
            agentId
            command
            clientUsername
            status
            output
            createdAt
            executedAt
          }
        }
      `;
      
      this.ws.send(JSON.stringify({
        type: 'graphql_query',
        query,
        agentId
      }));
    }
  }

  loadCommandHistory(agentId: string, limit: number = 50, offset: number = 0) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      const query = `
        query {
          commands(agentId: "${agentId}", limit: ${limit}, offset: ${offset}) {
            id
            agentId
            command
            clientUsername
            status
            output
            createdAt
            executedAt
          }
          commandCount(agentId: "${agentId}")
        }
      `;
      
      this.ws.send(JSON.stringify({
        type: 'graphql_query',
        query,
        agentId,
        loadHistory: true,
        isPaginated: true,
        offset: offset
      }));
    }
  }

  sendMessage(message: any) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  sendGraphQLQuery(query: string): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error("WebSocket not connected"));
        return;
      }

      const messageId = Date.now().toString();
      const message = {
        type: "graphql",
        id: messageId,
        query: query
      };

      const handleResponse = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (data.id === messageId) {
            this.ws?.removeEventListener('message', handleResponse);
            if (data.error) {
              reject(new Error(data.error));
            } else {
              // Update global state for real-time updates
              if (data.data && data.data.users) {
                this.users = data.data.users;
                this.notifyListeners();
              }
              if (data.data && data.data.listeners) {
                this.listeners = data.data.listeners;
                this.notifyListeners();
              }
              
              resolve({
                data: data.data,
                errors: data.errors
              });
            }
          }
        } catch (error) {
          console.error("Error parsing GraphQL response:", error);
        }
      };

      this.ws.addEventListener('message', handleResponse);
      this.ws.send(JSON.stringify(message));

      setTimeout(() => {
        this.ws?.removeEventListener('message', handleResponse);
        reject(new Error("GraphQL query timeout"));
      }, 10000);
    });
  }
}

// Hook that uses the singleton
export function useWebSocket(_isActive: boolean) {
  const { serverUrl } = useServerUrl();
  const [state, setState] = useState(() => {
    const manager = WebSocketManager.getInstance();
    return manager.getState();
  });

  useEffect(() => {
    const manager = WebSocketManager.getInstance();
    
    // Connect on first use with server URL
    manager.connect(serverUrl);
    
    // Subscribe to updates
    const listener = () => {
      setState(manager.getState());
    };
    
    manager.addListener(listener);
    
    return () => {
      manager.removeListener(listener);
    };
  }, [serverUrl]);

  return {
    agents: state.agents,
    isConnected: state.isConnected,
    commands: state.commands,
    commandTotalCounts: state.commandTotalCounts,
    users: state.users,
    listeners: state.listeners,
    handlers: state.handlers ?? [],
    ws: WebSocketManager.getInstance().getWebSocket(),
    sendCommand: (agentId: string, command: string, username: string = 'reaper') => {
      WebSocketManager.getInstance().sendCommand(agentId, command, username);
    },
    getCommands: (agentId: string) => {
      WebSocketManager.getInstance().getCommands(agentId);
    },
    loadCommandHistory: (agentId: string, limit?: number, offset?: number) => {
      WebSocketManager.getInstance().loadCommandHistory(agentId, limit, offset);
    },
    sendMessage: (message: any) => {
      WebSocketManager.getInstance().sendMessage(message);
    },
    sendGraphQLQuery: (query: string) => {
      return WebSocketManager.getInstance().sendGraphQLQuery(query);
    }
  };
}
