import React, {
  useState,
  useEffect,
  useRef,
  useMemo,
  useCallback,
} from "react";
import { IoSend } from "react-icons/io5";
import { SiOllama } from "react-icons/si";
import { FaUserSecret, FaPlay, FaCheckCircle, FaExclamationTriangle, FaSpinner, FaThumbsUp, FaQuestion } from "react-icons/fa";
import ReactMarkdown from "react-markdown";
import { useWebSocket } from "../hooks/useWebSocket";
import { useAuth } from "../contexts/AuthContext";
import "./AI.css";

interface AIProps {
  isActive: boolean;
}

interface Model {
  id: string;
  name: string;
  provider?: string;
}

interface Agent {
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

interface Command {
  id: number;
  agentId: string;
  command: string;
  clientUsername: string;
  status: string;
  output: string;
  createdAt: string;
  executedAt?: string | null;
}

interface AgentContextData {
  agent: Agent;
  commands: Command[];
}

type ChatRole = "system" | "user" | "assistant";

interface ChatMessage {
  id?: string;
  role: ChatRole;
  content: string;
  createdAt?: string;
  metadata?: Record<string, unknown>;
}

interface AgentChatTab {
  tabId: string;
  agentId: string;
  agentName: string;
  agentStatus: string;
  agentIp: string;
  agentOs: string;
  agentLastSeen: string;
  agentCreatedAt: string;
  reconnectInterval?: number;
  conversationId: string | null;
  contextPrompt: string;
  commandHistory: Command[];
  messages: ChatMessage[];
  isLoading: boolean;
  isStreaming: boolean;
  streamingContent: string;
  error: string | null;
}

const GRAPHQL_ENDPOINT = "https://localhost:8443/graphql";
const CONVERSATION_STORAGE_KEY = "openwebui_agent_conversations";
const CHAT_TABS_STORAGE_KEY = "openwebui_agent_chat_tabs";
const ACTIVE_TAB_STORAGE_KEY = "openwebui_agent_active_tab";
const MAX_COMMAND_HISTORY = 50;
const COMMAND_TAG_REGEX = /<\s*(?:cmdankou|ankoucmd)\s*>([\s\S]*?)<\/\s*(?:cmdankou|ankoucmd)\s*>/gi;

interface MessageSegment {
  type: "markdown" | "command";
  value: string;
}

const splitMessageSegments = (content: string): MessageSegment[] => {
  if (!content || typeof content !== "string") {
    return [];
  }

  const segments: MessageSegment[] = [];
  const regex = new RegExp(COMMAND_TAG_REGEX.source, "gi");
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(content)) !== null) {
    if (match.index > lastIndex) {
      const markdownPart = content.slice(lastIndex, match.index);
      if (markdownPart.trim().length > 0) {
        segments.push({ type: "markdown", value: markdownPart });
      }
    }

    const command = match[1].replace(/^[\s,]+|[\s,]+$/g, "").trim();
    if (command.length > 0) {
      segments.push({ type: "command", value: command });
    }

    lastIndex = regex.lastIndex;
  }

  if (lastIndex < content.length) {
    const tail = content.slice(lastIndex);
    if (tail.trim().length > 0) {
      segments.push({ type: "markdown", value: tail });
    }
  }

  return segments;
};

const normalizeCommandFormatting = (content: string): string => {
  if (!content || typeof content !== "string") {
    return "";
  }

  return content.replace(/```[\w-]*\s*([\s\S]*?)```/g, (match, inner) => {
    if (inner.includes("<cmdankou>")) {
      return inner.trim();
    }
    return match;
  });
};

// ClickableCommand component for executing commands from AI responses
// Usage: AI can return text with <cmdankou>command</cmdankou> tags
// These will be rendered as clickable buttons that execute the command
// Example: "To check processes, run <cmdankou>ps</cmdankou>"
interface ClickableCommandProps {
  command: string;
  chatTabs: AgentChatTab[];
  activeChatTabId: string | null;
  modelName?: string;
}

function ClickableCommand({ command, chatTabs, activeChatTabId, modelName }: ClickableCommandProps) {
  const { user } = useAuth();
  const [status, setStatus] = useState<'idle' | 'executing' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [trackedCommandId, setTrackedCommandId] = useState<number | null>(null);
  const [commandAnchorId, setCommandAnchorId] = useState<number | null>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { sendCommand, sendMessage, commands: commandState } = useWebSocket(true);

  const activeTab = chatTabs.find((tab) => tab.tabId === activeChatTabId);
  const activeAgentId = activeTab?.agentId ?? null;

  const clearStatusTimeout = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  const handleCommandStatusTransition = useCallback(
    (cmd: Command) => {
      if (cmd.status === 'pending') {
        if (status !== 'executing') {
          setStatus('executing');
        }
        return;
      }

      if (cmd.status === 'completed') {
        if (status !== 'success') {
          setErrorMessage('');
          setStatus('success');
        }
        if (!timeoutRef.current) {
          clearStatusTimeout();
          timeoutRef.current = setTimeout(() => {
            setStatus('idle');
            setTrackedCommandId(null);
            setCommandAnchorId(null);
            timeoutRef.current = null;
          }, 3000);
        }
        return;
      }

      if (cmd.status === 'error') {
        if (status !== 'error') {
          setStatus('error');
          setErrorMessage((cmd.output ?? '').trim() || 'Failed to execute command');
        }
        if (!timeoutRef.current) {
          clearStatusTimeout();
          timeoutRef.current = setTimeout(() => {
            setStatus('idle');
            setErrorMessage('');
            setTrackedCommandId(null);
            setCommandAnchorId(null);
            timeoutRef.current = null;
          }, 5000);
        }
        return;
      }

      if (status !== 'executing') {
        setStatus('executing');
      }
    },
    [clearStatusTimeout, status]
  );

  useEffect(() => {
    return () => {
      clearStatusTimeout();
    };
  }, [clearStatusTimeout]);

  useEffect(() => {
    if (!activeAgentId) {
      return;
    }

    if (status === 'idle') {
      return;
    }

    const agentCommands = commandState[activeAgentId];
    if (!agentCommands || agentCommands.length === 0) {
      return;
    }

    const anchor = commandAnchorId ?? 0;
    const candidates = agentCommands.filter(
      (cmd) =>
        cmd.clientUsername === 'ai-assistant' &&
        cmd.command === command &&
        cmd.id > anchor
    );

    if (trackedCommandId === null) {
      const candidate = candidates[candidates.length - 1];
      if (!candidate) {
        return;
      }
      setTrackedCommandId(candidate.id);
      handleCommandStatusTransition(candidate);
      return;
    }

    const tracked = agentCommands.find((cmd) => cmd.id === trackedCommandId);
    if (tracked) {
      handleCommandStatusTransition(tracked);
    }
  }, [
    activeAgentId,
    command,
    commandAnchorId,
    commandState,
    handleCommandStatusTransition,
    status,
    trackedCommandId,
  ]);

  useEffect(() => {
    clearStatusTimeout();
    setTrackedCommandId(null);
    setCommandAnchorId(null);
    setStatus('idle');
    setErrorMessage('');
  }, [activeAgentId, clearStatusTimeout]);

  const handleExecute = async () => {
    if (status === 'executing') return;
    
    clearStatusTimeout();
    setStatus('executing');
    setErrorMessage('');
    setTrackedCommandId(null);
    setCommandAnchorId(null);

    try {
      if (activeAgentId) {
        const existing = commandState[activeAgentId] || [];
        const highestId = existing.reduce(
          (max, cmd) => (cmd.id > max ? cmd.id : max),
          0
        );
        setCommandAnchorId(highestId);
        sendCommand(activeAgentId, command, `${user?.username || 'operator'} via ${modelName || 'ai'}`);
      } else {
        sendMessage({
          type: "global_command",
          command: command,
          username: `${user?.username || 'operator'} via ${modelName || 'ai'}`
        });

        timeoutRef.current = setTimeout(() => {
          setStatus('success');
          timeoutRef.current = setTimeout(() => {
            setStatus('idle');
            setErrorMessage('');
            timeoutRef.current = null;
          }, 3000);
        }, 1000);
        return;
      }
    } catch (error) {
      setStatus('error');
      setErrorMessage(error instanceof Error ? error.message : 'Failed to execute command');
      timeoutRef.current = setTimeout(() => {
        setStatus('idle');
        setErrorMessage('');
        setTrackedCommandId(null);
        setCommandAnchorId(null);
        timeoutRef.current = null;
      }, 5000);
    }
  };

  const renderStatusIndicator = () => {
    if (status === 'executing') {
      return (
        <span className="command-status executing">
          <FaSpinner className="command-status-icon" />
          Running...
        </span>
      );
    }
    if (status === 'success') {
      return (
        <span className="command-status success">
          <FaCheckCircle className="command-status-icon" />
          Ran
        </span>
      );
    }
    if (status === 'error') {
      return (
        <span className="command-status error">
          <FaExclamationTriangle className="command-status-icon" />
          Error
        </span>
      );
    }
    return null;
  };

  return (
    <div className="command-suggestion">
      <div className="command-suggestion-line">
        <span className="command-suggestion-prompt">$</span>
        <code className="command-suggestion-text">{command}</code>
      </div>
      <div className="command-suggestion-actions">
        <button
          className="command-run-button"
          onClick={handleExecute}
          disabled={status === 'executing'}
          title={`${activeTab?.agentId ? `Execute on ${activeTab.agentName || activeTab.agentId}` : 'Execute globally'}: ${command}`}
        >
          {status === 'executing' ? (
            <FaSpinner className="command-run-icon" />
          ) : (
            <FaPlay className="command-run-icon" />
          )}
          Run
        </button>
        {renderStatusIndicator()}
      </div>
      {errorMessage && (
        <div className="command-error">
          {errorMessage}
        </div>
      )}
    </div>
  );
}

const extractConversationId = (data: any): string | null => {
  if (!data) return null;
  if (typeof data === "string") {
    return data.trim() || null;
  }

  const candidates = [
    data.id,
    data.ID,
    data.conversationId,
    data.conversation_id,
    data?.conversation?.id,
    data?.conversation?.conversation_id,
    data?.conversation?.uuid,
    data?.data?.id,
    data?.conversationID,
    data?.metadata?.conversation_id,
    data?.uuid,
    data?.conversation_uuid,
  ];

  for (const candidate of candidates) {
    if (candidate && typeof candidate === "string" && candidate.trim().length) {
      return candidate.trim();
    }
  }

  if (Array.isArray(data)) {
    for (const item of data) {
      const nested = extractConversationId(item);
      if (nested) return nested;
    }
  }

  return null;
};

const formatTimestamp = (value?: string) => {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
};

const normaliseMessageContent = (message: any): string => {
  if (!message) return "";

  if (typeof message === "string") {
    return message;
  }

  if (typeof message.content === "string") {
    return message.content;
  }

  if (Array.isArray(message.content)) {
    return message.content
      .map((part: any) => {
        if (typeof part === "string") return part;
        if (typeof part?.text === "string") return part.text;
        if (typeof part?.content === "string") return part.content;
        return "";
      })
      .join("");
  }

  if (typeof message.message === "string") {
    return message.message;
  }

  if (Array.isArray(message.parts)) {
    return message.parts
      .map((part: any) => {
        if (typeof part === "string") return part;
        if (typeof part?.text === "string") return part.text;
        return "";
      })
      .join("");
  }

  if (typeof message.text === "string") {
    return message.text;
  }

  return "";
};

const mapConversationMessages = (rawMessages: any[]): ChatMessage[] => {
  if (!Array.isArray(rawMessages)) return [];

  return rawMessages
    .filter(
      (msg) => msg && (msg.role === "user" || msg.role === "assistant")
    )
    .map((msg) => ({
      id: msg.id ?? msg.message_id ?? undefined,
      role: msg.role,
      content: normaliseMessageContent(msg),
      createdAt: msg.created_at ?? msg.timestamp ?? undefined,
      metadata:
        typeof msg.metadata === "object" && msg.metadata !== null
          ? msg.metadata
          : undefined,
    }));
};

const buildAgentContextPrompt = (
  agent: Agent,
  commands: Command[],
  handlers: any[] = []
): string => {
  const agentHandler = handlers.find(handler => 
    handler.agentHttpHeaderId === agent.handlerId || 
    handler.agentName === agent.handlerName
  );
  
  const lines: string[] = [
    "You are assisting a penetration tester using a C2 (Command & Control) framework.",
    "Your role is to help the operator understand and interact with compromised endpoints.",
    "",
    `=== TARGET AGENT ===`,
    `Agent: ${agent.name}`,
    `IP: ${agent.ip}`,
    `OS: ${agent.os}`,
    `Status: Last seen ${formatTimestamp(agent.lastSeen)}`,
    `Beacon Interval: ${agent.reconnectInterval || 'unknown'} seconds`,
    "",
  ];
  
  if (agentHandler?.supportedCommands && agentHandler.supportedCommands.length > 0) {
    lines.push(
      "=== AVAILABLE COMMANDS ===",
      "The following base commands are supported by this agent:",
      ...agentHandler.supportedCommands.map(cmd => `  • ${cmd}`),
      "",
      "These commands can accept standard arguments, flags, and paths.",
      "Examples:",
      "  • <ankoucmd>ls /home</ankoucmd> - List files with details",
      "  • <ankoucmd>ps</ankoucmd> - Show all processes",
      "  • <ankoucmd>cd /etc</ankoucmd> - Change directory",
      "  • <ankoucmd>get /etc/passwd</ankoucmd> - Download a file",
      "",
    );
  }

  const history = commands.slice(-MAX_COMMAND_HISTORY); // Keep last 50 commands

  if (history.length === 0) {
    lines.push(
      "=== COMMAND HISTORY ===",
      "No commands have been executed on this agent yet.",
      ""
    );
  } else {
    lines.push(
      "=== COMMAND HISTORY ===",
      `Showing last ${history.length} command(s):`,
      ""
    );
    history.forEach((command, index) => {
      const timestamp = formatTimestamp(command.createdAt);
      const statusEmoji = command.status === 'completed' ? '✓' : command.status === 'error' ? '✗' : '○';
      
      lines.push(`[${index + 1}] ${timestamp} • ${command.clientUsername}`);
      lines.push(`    Command: ${command.command}`);
      lines.push(`    Status: ${statusEmoji} ${command.status}`);
      
      if (command.output && command.output.trim().length > 0) {
        const outputPreview = command.output.length > 500 
          ? command.output.substring(0, 500) + '... (truncated)'
          : command.output;
        lines.push(`    Output:\n${outputPreview}`);
      } else {
        lines.push(`    Output: (no output)`);
      }
      lines.push("");
    });
  }

  lines.push(
    "=== INSTRUCTIONS ===",
    "1. Answer questions about the agent using the context above",
    "2. Suggest relevant commands to help the operator achieve their goals",
    "3. When suggesting a command, wrap it in <ankoucmd>command here</ankoucmd> tags",
    "4. The wrapped command becomes a clickable button for easy execution",
    "5. Be proactive - suggest useful next steps based on command history",
    "",
    "Command Format Rules:",
    "  • Include the full command with all arguments inside the tags",
    "  • Do NOT add punctuation (commas, periods) inside the tags",
    "  • Do NOT wrap tags in markdown code blocks",
    "  • Keep commands clean and executable",
    "",
    "Good: <ankoucmd>ls -la /tmp</ankoucmd>",
    "Bad: <ankoucmd>ls -la /tmp,</ankoucmd> or ```<ankoucmd>ls</ankoucmd>```",
    "",
    "Remember: This is an authorized penetration test. Focus on C2 operations and reconnaissance.",
  );

  const finalPrompt = lines.join("\n");
  return finalPrompt;
};

const commandsDiffer = (previous: Command[], next: Command[]) => {
  if (previous.length !== next.length) {
    return true;
  }

  for (let i = 0; i < next.length; i += 1) {
    const prev = previous[i];
    const curr = next[i];
    if (
      !prev ||
      prev.id !== curr.id ||
      prev.status !== curr.status ||
      (prev.output ?? "") !== (curr.output ?? "") ||
      (prev.executedAt ?? "") !== (curr.executedAt ?? "")
    ) {
      return true;
    }
  }

  return false;
};

const collectCommandUpdates = (previous: Command[], next: Command[]) => {
  const previousById = new Map(previous.map((command) => [command.id, command]));

  return next.filter((command) => {
    const prior = previousById.get(command.id);

    // Skip commands that are still pending with no output.
    if (command.status === "pending" && !(command.output ?? "").trim().length) {
      return false;
    }

    if (!prior) {
      // New command with a meaningful status or output.
      return command.status !== "pending" || !!(command.output ?? "").trim();
    }

    const statusChanged = prior.status !== command.status;
    const outputChanged = (prior.output ?? "") !== (command.output ?? "");

    return statusChanged || outputChanged;
  });
};

const buildCommandUpdateMessage = (command: Command): ChatMessage => {
  const rawOutput = (command.output ?? "").trim();

  return {
    id: `command-${command.id}-${command.executedAt ?? Date.now()}`,
    role: "assistant",
    content: rawOutput,
    createdAt: new Date().toISOString(),
    metadata: {
      type: "command_output",
      command: command.command,
      status: command.status,
      hasOutput: rawOutput.length > 0,
    },
  };
};

const isCommandOutputMessage = (
  message: ChatMessage
): message is ChatMessage & {
  metadata: {
    type: "command_output";
    command?: string;
    status?: string;
    hasOutput?: boolean;
  };
} => message.metadata?.type === "command_output";

const loadStoredConversations = () => {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(CONVERSATION_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
};

const loadStoredChatTabs = (): AgentChatTab[] => {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(CHAT_TABS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const loadStoredActiveTab = (): string | null => {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem(ACTIVE_TAB_STORAGE_KEY);
  } catch {
    return null;
  }
};

const saveChatTabs = (tabs: AgentChatTab[]) => {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(CHAT_TABS_STORAGE_KEY, JSON.stringify(tabs));
  } catch (error) {
    console.warn("Failed to save chat tabs:", error);
  }
};

const saveActiveTab = (tabId: string | null) => {
  if (typeof window === "undefined") return;
  try {
    if (tabId) {
      localStorage.setItem(ACTIVE_TAB_STORAGE_KEY, tabId);
    } else {
      localStorage.removeItem(ACTIVE_TAB_STORAGE_KEY);
    }
  } catch (error) {
    console.warn("Failed to save active tab:", error);
  }
};

export default function AI({ isActive }: AIProps) {
  const { user } = useAuth();
  const [url, setUrl] = useState("");
  const [jwt, setJwt] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [models, setModels] = useState<Model[]>([]);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [selectedModel, setSelectedModel] = useState<Model | null>(null);

  const [agents, setAgents] = useState<Agent[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [agentsError, setAgentsError] = useState<string | null>(null);
  const [agentFilter, setAgentFilter] = useState("");

  const [chatTabs, setChatTabs] = useState<AgentChatTab[]>(() => loadStoredChatTabs());
  const [activeChatTabId, setActiveChatTabId] = useState<string | null>(() => loadStoredActiveTab());
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [tabInputs, setTabInputs] = useState<Record<string, string>>({});
  const [conversationMap, setConversationMap] = useState<
    Record<string, string>
  >(() => loadStoredConversations());
  const { commands: commandState, handlers } = useWebSocket(true);
  
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

  // Format last seen time
  const formatLastSeen = (lastSeen: string) => {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };
  

  const markdownComponents = useMemo(
    () => ({
      a: ({
        node,
        ...props
      }: React.ComponentPropsWithoutRef<"a"> & { node?: unknown }) => (
        <a
          {...props}
          target="_blank"
          rel="noopener noreferrer"
          className="markdown-link"
        />
      ),
      code: ({
        inline,
        className,
        children,
        ...props
      }: React.ComponentPropsWithoutRef<"code"> & {
        inline?: boolean;
        node?: unknown;
      }) => {
        const content = String(children).replace(/\n$/, "");
        if (inline) {
          return (
            <code
              className={`inline-code ${className ? className : ""}`.trim()}
              {...props}
            >
              {content}
            </code>
          );
        }
        return (
          <pre
            className={`code-block ${className ? className : ""}`.trim()}
          >
            <code {...props}>{content}</code>
          </pre>
        );
      },
    }),
    []
  );

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const streamingMessageRef = useRef<Record<string, string>>({});

  const normalisedOpenWebUIUrl = useMemo(() => {
    if (!url) return null;
    return url.endsWith("/") ? url : `${url}/`;
  }, [url]);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const cachedUrl = localStorage.getItem("openwebui_url");
    const cachedJwt = localStorage.getItem("openwebui_jwt");
    const cachedModels = localStorage.getItem("openwebui_models");
    const cachedLogin = localStorage.getItem("openwebui_logged_in");
    const cachedModel = localStorage.getItem("openwebui_selected_model");

    if (cachedUrl) {
      setUrl(cachedUrl);
    }
    if (cachedJwt) {
      setJwt(cachedJwt);
    }
    if (cachedModels) {
      try {
        const parsedModels: Model[] = JSON.parse(cachedModels);
        setModels(parsedModels);
        if (cachedModel) {
          try {
            const parsedModel: Model = JSON.parse(cachedModel);
            const match = parsedModels.find((m) => m.id === parsedModel.id);
            if (match) {
              setSelectedModel(match);
            }
          } catch {
            // ignore parse errors
          }
        }
      } catch {
        // ignore
      }
    }
    if (cachedLogin === "true" && cachedUrl && cachedJwt) {
      setIsLoggedIn(true);
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    localStorage.setItem(
      CONVERSATION_STORAGE_KEY,
      JSON.stringify(conversationMap)
    );
  }, [conversationMap]);

  useEffect(() => {
    if (!activeChatTabId) return;
    const activeTab = chatTabs.find((tab) => tab.tabId === activeChatTabId);
    if (activeTab && !activeTab.isLoading) {
      const timer = window.setTimeout(() => {
        textareaRef.current?.focus();
      }, 120);
      return () => clearTimeout(timer);
    }
  }, [activeChatTabId, chatTabs]);

  useEffect(() => {
    const activeTab = chatTabs.find((tab) => tab.tabId === activeChatTabId);
    if (!activeTab) return;
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatTabs, activeChatTabId]);

  const fetchGraphQL = useCallback(
    async (query: string, variables: Record<string, unknown> = {}) => {
      const response = await fetch(GRAPHQL_ENDPOINT, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query, variables }),
      });

      if (!response.ok) {
        throw new Error(`GraphQL request failed with status ${response.status}`);
      }

      const result = await response.json();
      if (result.errors && result.errors.length > 0) {
        throw new Error(result.errors[0].message || "GraphQL error");
      }

      return result.data;
    },
    []
  );

  const loadAgents = useCallback(async () => {
    setAgentsLoading(true);
    setAgentsError(null);

    try {
      const data = await fetchGraphQL(`
        query {
          agents {
            id
            name
            status
            ip
            lastSeen
            os
            createdAt
            handlerId
            handlerName
          }
        }
      `);

      setAgents(data?.agents ?? []);
    } catch (err) {
      setAgentsError(
        err instanceof Error ? err.message : "Failed to load agents."
      );
    } finally {
      setAgentsLoading(false);
    }
  }, [fetchGraphQL]);

  useEffect(() => {
    if (!isActive || !isLoggedIn) return;
    loadAgents();
  }, [isActive, isLoggedIn, loadAgents]);

  useEffect(() => {
    if (agents.length === 0) return;
    setChatTabs((prev) =>
      prev.map((tab) => {
        const agent = agents.find((item) => item.id === tab.agentId);
        if (!agent) return tab;
        return {
          ...tab,
          agentName: agent.name,
          agentStatus: agent.status,
          agentIp: agent.ip,
          agentOs: agent.os,
          agentLastSeen: agent.lastSeen,
          reconnectInterval: agent.reconnectInterval,
          agentCreatedAt: agent.createdAt,
        };
      })
    );
  }, [agents]);

  useEffect(() => {
    if (!isLoggedIn) return;

    setChatTabs((prevTabs) => {
      let mutated = false;

      const nextTabs = prevTabs.map((tab) => {
        const agentCommands = commandState[tab.agentId];
        if (!agentCommands || agentCommands.length === 0) {
          return tab;
        }

        const previousHistory = tab.commandHistory ?? [];
        if (!commandsDiffer(previousHistory, agentCommands)) {
          return tab;
        }

        const clonedCommands = agentCommands.map((command) => ({ ...command }));
        const skipMessages =
          previousHistory.length === 0 && tab.messages.length === 0;

        const updates = skipMessages
          ? []
          : collectCommandUpdates(previousHistory, agentCommands);

        const agentForPrompt: Agent = {
          id: tab.agentId,
          name: tab.agentName,
          status: tab.agentStatus,
          ip: tab.agentIp,
          os: tab.agentOs,
          lastSeen: tab.agentLastSeen,
          createdAt: tab.agentCreatedAt || new Date().toISOString(),
        };

        const updatedPrompt = buildAgentContextPrompt(
          agentForPrompt,
          clonedCommands,
          handlers
        );

        const updatedMessages =
          updates.length > 0
            ? [...tab.messages, ...updates.map(buildCommandUpdateMessage)]
            : tab.messages;

        mutated = true;

        return {
          ...tab,
          contextPrompt: updatedPrompt,
          commandHistory: clonedCommands,
          messages: updatedMessages,
        };
      });

      return mutated ? nextTabs : prevTabs;
    });
  }, [commandState, isLoggedIn, handlers]);

  // Persist chat tabs to localStorage
  useEffect(() => {
    if (typeof window === "undefined") return;
    saveChatTabs(chatTabs);
  }, [chatTabs]);

  // Persist active tab to localStorage
  useEffect(() => {
    if (typeof window === "undefined") return;
    saveActiveTab(activeChatTabId);
  }, [activeChatTabId]);

  const filteredAgents = useMemo(() => {
    if (!agentFilter) return agents;
    const lower = agentFilter.toLowerCase();
    return agents.filter(
      (agent) =>
        agent.name.toLowerCase().includes(lower) ||
        agent.id.toLowerCase().includes(lower) ||
        agent.ip.toLowerCase().includes(lower)
    );
  }, [agents, agentFilter]);

  const fetchAgentContext = useCallback(
    async (agentId: string): Promise<AgentContextData> => {
      const data = await fetchGraphQL(
        `
        query AgentContext($agentId: String!) {
          agentContext(agentId: $agentId) {
            agent {
              id
              name
              status
              ip
              lastSeen
              os
              createdAt
              handlerId
              handlerName
            }
            commands {
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
        }
      `,
        { agentId }
      );

      if (!data?.agentContext?.agent) {
        throw new Error("Agent context not found.");
      }

      return {
        agent: data.agentContext.agent,
        commands: data.agentContext.commands ?? [],
      };
    },
    [fetchGraphQL]
  );

  const handleOpenWebUIAuthFailure = useCallback(
    (message?: string) => {
      setIsLoggedIn(false);
      setSelectedModel(null);
      setChatTabs([]);
      setActiveChatTabId(null);
      setTabInputs({});
      setConversationMap({});
      streamingMessageRef.current = {};
      setError(
        message ||
          "Open WebUI authentication failed. Please re-enter your URL and JWT token."
      );

      if (typeof window !== "undefined") {
        localStorage.removeItem("openwebui_logged_in");
        localStorage.removeItem("openwebui_jwt");
        localStorage.removeItem("openwebui_selected_model");
        localStorage.removeItem(CONVERSATION_STORAGE_KEY);
      }
    },
    []
  );

  const openWebUIRequest = useCallback(
    async (path: string, init: RequestInit = {}) => {
      if (!normalisedOpenWebUIUrl || !jwt) {
        handleOpenWebUIAuthFailure(
          "Open WebUI connection is not configured. Please enter your URL and JWT token."
        );
        throw new Error("Open WebUI connection is not configured.");
      }

      const method = (init.method || "GET").toUpperCase();
      const headers = new Headers(init.headers || {});
      headers.set("Authorization", `Bearer ${jwt}`);
      if (!headers.has("Accept")) {
        headers.set("Accept", "application/json");
      }

      const isBodyFormData =
        typeof FormData !== "undefined" && init.body instanceof FormData;
      if (method !== "GET" && method !== "HEAD") {
        if (!isBodyFormData && !headers.has("Content-Type")) {
          headers.set("Content-Type", "application/json");
        }
      } else if (headers.has("Content-Type") && !isBodyFormData) {
        headers.delete("Content-Type");
      }

      const response = await fetch(`${normalisedOpenWebUIUrl}${path}`, {
        ...init,
        method,
        headers,
      });

      const raw = await response.text();
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          handleOpenWebUIAuthFailure(
            "Open WebUI rejected the JWT. Please re-authenticate."
          );
        }

        const summary = raw ? `: ${raw.slice(0, 200)}` : "";
        const error = new Error(
          `Open WebUI request failed (${method} ${path} -> ${response.status})${summary}`
        );
        (error as any).status = response.status;
        (error as any).body = raw;
        (error as any).method = method;
        (error as any).path = path;
        throw error;
      }

      if (!raw) {
        return null;
      }

      try {
        return JSON.parse(raw);
      } catch {
        return raw;
      }
    },
    [handleOpenWebUIAuthFailure, jwt, normalisedOpenWebUIUrl]
  );

  const fetchConversationById = useCallback(
    async (conversationId: string) => {
      let lastError: unknown = null;

      const attempts: Array<() => Promise<any[]>> = [
        async () => {
          const data = await openWebUIRequest(
            `api/conversations/${conversationId}`,
            { method: "GET" }
          );

          if (data?.conversation?.messages) {
            return data.conversation.messages;
          }
          if (Array.isArray(data?.messages)) {
            return data.messages;
          }
          return Array.isArray(data) ? data : [];
        },
        async () => {
          const data = await openWebUIRequest(
            `api/conversations/${conversationId}/messages`,
            { method: "GET" }
          );
          if (Array.isArray(data?.messages)) {
            return data.messages;
          }
          return Array.isArray(data) ? data : [];
        },
        async () => {
          const data = await openWebUIRequest(
            `api/chat/conversations/${conversationId}`,
            { method: "GET" }
          );
          if (Array.isArray(data?.messages)) {
            return data.messages;
          }
          if (data?.conversation?.messages) {
            return data.conversation.messages;
          }
          return Array.isArray(data) ? data : [];
        },
        async () => {
          const data = await openWebUIRequest(
            `api/chat/conversations/${conversationId}/messages`,
            { method: "GET" }
          );
          if (Array.isArray(data?.messages)) {
            return data.messages;
          }
          return Array.isArray(data) ? data : [];
        },
      ];

      for (const attempt of attempts) {
        try {
          const result = await attempt();
          return result;
        } catch (err) {
          lastError = err;
          const status = (err as any)?.status;
          if (status && ![404, 405, 501].includes(status)) {
            throw err;
          }
        }
      }

      if (lastError) {
        const status = (lastError as any)?.status;
        if (status && [404, 405, 501].includes(status)) {
          return [];
        }
        throw lastError;
      }

      return [];
    },
    [openWebUIRequest]
  );

  const initializeAgentTab = useCallback(
    async (tabId: string, agent: Agent) => {
      setChatTabs((prev) =>
        prev.map((tab) =>
          tab.tabId === tabId ? { ...tab, isLoading: true, error: null } : tab
        )
      );

      try {
        const context = await fetchAgentContext(agent.id);
        const contextPrompt = buildAgentContextPrompt(
          context.agent,
          context.commands,
          handlers
        );

        let conversationId = conversationMap[agent.id] || null;
        let existingMessages: ChatMessage[] = [];

        if (conversationId) {
          try {
            const rawMessages = await fetchConversationById(conversationId);
            existingMessages = mapConversationMessages(rawMessages).filter(
              (message) => message.role !== "system"
            );
          } catch (err) {
            if ((err as any).status === 404) {
              setConversationMap((prev) => {
                const updated = { ...prev };
                delete updated[agent.id];
                return updated;
              });
              conversationId = null;
            } else {
              throw err;
            }
          }
        }

        setChatTabs((prev) =>
          prev.map((tab) =>
            tab.tabId === tabId
              ? {
                  ...tab,
                  conversationId,
                  contextPrompt,
                  commandHistory: (context.commands ?? []).map((command) => ({
                    ...command,
                  })),
                  agentCreatedAt:
                    context.agent?.createdAt ?? tab.agentCreatedAt,
                  messages: existingMessages,
                  isLoading: false,
                  error: null,
                }
              : tab
          )
        );
      } catch (err) {
        setChatTabs((prev) =>
          prev.map((tab) =>
            tab.tabId === tabId
              ? {
                  ...tab,
                  isLoading: false,
                  error:
                    err instanceof Error
                      ? err.message
                      : "Failed to prepare conversation.",
                }
              : tab
          )
        );
      }
    },
    [conversationMap, fetchAgentContext, fetchConversationById, handlers]
  );

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url || !jwt) {
      setError("Please fill in both URL and JWT");
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${url.endsWith('/') ? url : url + '/'}api/models`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${jwt}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch models: ${response.status}`);
      }

      const responseText = await response.text();
      let modelsData;
      try {
        modelsData = JSON.parse(responseText);
      } catch {
        throw new Error(
          `Invalid JSON response. Response: ${responseText.slice(0, 100)}`
        );
      }

      let modelsList: Model[] = [];

      if (Array.isArray(modelsData)) {
        modelsList = modelsData.map((model: any) => ({
          id: model.id || model.name,
          name: model.name || model.id,
          provider: model.provider || model.source,
        }));
      } else if (Array.isArray(modelsData?.data)) {
        modelsList = modelsData.data.map((model: any) => ({
          id: model.id || model.name,
          name: model.name || model.id,
          provider: model.provider || model.source,
        }));
      } else if (Array.isArray(modelsData?.models)) {
        modelsList = modelsData.models.map((model: any) => ({
          id: model.id || model.name,
          name: model.name || model.id,
          provider: model.provider || model.source,
        }));
      }

      if (modelsList.length === 0) {
        throw new Error("No models found in the response");
      }

      setModels(modelsList);
      setIsLoggedIn(true);

      localStorage.setItem("openwebui_url", url);
      localStorage.setItem("openwebui_jwt", jwt);
      localStorage.setItem("openwebui_models", JSON.stringify(modelsList));
      localStorage.setItem("openwebui_logged_in", "true");

      const cachedModel = localStorage.getItem("openwebui_selected_model");
      if (cachedModel) {
        try {
          const parsedModel: Model = JSON.parse(cachedModel);
          const matched = modelsList.find((m) => m.id === parsedModel.id);
          if (matched) {
            setSelectedModel(matched);
          }
        } catch {
          // ignore
        }
      }

      loadAgents();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect. Please check your URL and JWT."
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleModelSelect = (modelId: string) => {
    const model = models.find((m) => m.id === modelId) || null;
    setSelectedModel(model);
    if (model) {
      localStorage.setItem("openwebui_selected_model", JSON.stringify(model));
    } else {
      localStorage.removeItem("openwebui_selected_model");
    }
  };

  const renderMessageContent = useCallback(
    (message: ChatMessage) => {
      if (isCommandOutputMessage(message)) {
        const commandText =
          typeof message.metadata.command === "string"
            ? message.metadata.command
            : "";
        const statusText =
          typeof message.metadata.status === "string"
            ? message.metadata.status
            : "";
        const statusLabel =
          statusText.length > 0
            ? statusText.charAt(0).toUpperCase() + statusText.slice(1)
            : "";
        const statusClass = statusText
          ? (() => {
              const normalized = statusText.toLowerCase();
              if (normalized === "completed" || normalized === "success") {
                return "ai-command-status-complete";
              }
              if (normalized === "error" || normalized === "failed") {
                return "ai-command-status-error";
              }
              return "ai-command-status-default";
            })()
          : "ai-command-status-default";
        const outputText =
          typeof message.content === "string" ? message.content : "";
        const hasOutput =
          message.metadata.hasOutput === true || outputText.trim().length > 0;

        return (
          <div className="ai-command-block">
            {commandText && (
              <div className="ai-command-line">
                <span className="ai-command-prompt">$</span>
                <code className="ai-command-text">{commandText}</code>
                {statusLabel && (
                  <span className={`ai-command-status ${statusClass}`}>
                    {statusLabel}
                  </span>
                )}
              </div>
            )}
            {hasOutput ? (
              <pre className="ai-command-output">{outputText.trimEnd()}</pre>
            ) : (
              <div className="ai-command-output ai-command-output-empty">No output returned.</div>
            )}
          </div>
        );
      }

      const rawContent =
        typeof message.content === "string" ? message.content : "";
      const normalizedContent = normalizeCommandFormatting(rawContent);

      if (!normalizedContent.trim().length) {
        return null;
      }

      const keyPrefix = message.id ?? message.createdAt ?? `${Date.now()}`;

      const segments = splitMessageSegments(normalizedContent);
      if (segments.length === 0) {
        return (
          <ReactMarkdown
            key={`md-${keyPrefix}-0`}
            components={markdownComponents}
            className="markdown-segment"
          >
            {normalizedContent}
          </ReactMarkdown>
        );
      }

      return segments.map((segment, index) => {
        if (segment.type === "command") {
          return (
            <ClickableCommand
              key={`command-${keyPrefix}-${index}`}
              command={segment.value}
              chatTabs={chatTabs}
              activeChatTabId={activeChatTabId}
              modelName={selectedModel?.name}
            />
          );
        }

        if (!segment.value.trim().length) {
          return null;
        }

        return (
          <ReactMarkdown
            key={`md-${keyPrefix}-${index}`}
            components={markdownComponents}
            className="markdown-segment"
          >
            {segment.value}
          </ReactMarkdown>
        );
      });
    },
    [activeChatTabId, chatTabs, markdownComponents]
  );

  const handleOpenAgentTab = (agent: Agent) => {
    // Set the selected agent
    setSelectedAgentId(agent.id);
    
    const existing = chatTabs.find((tab) => tab.agentId === agent.id);
    if (existing) {
      setActiveChatTabId(existing.tabId);
      return;
    }

    const tabId = agent.id;
    const newTab: AgentChatTab = {
      tabId,
      agentId: agent.id,
      agentName: agent.name,
      agentStatus: agent.status,
      agentIp: agent.ip,
      agentOs: agent.os,
      agentLastSeen: agent.lastSeen,
      reconnectInterval: agent.reconnectInterval,
      agentCreatedAt: agent.createdAt,
      conversationId: conversationMap[agent.id] || null,
      contextPrompt: "",
      commandHistory: [],
      messages: [],
      isLoading: true,
      isStreaming: false,
      streamingContent: "",
      error: null,
    };

    setChatTabs((prev) => [...prev, newTab]);
    setActiveChatTabId(tabId);
    initializeAgentTab(tabId, agent);
  };

  const handleCloseTab = (tabId: string) => {
    setChatTabs((prev) => prev.filter((tab) => tab.tabId !== tabId));
    setTabInputs((prev) => {
      const updated = { ...prev };
      delete updated[tabId];
      return updated;
    });

    delete streamingMessageRef.current[tabId];

    if (activeChatTabId === tabId) {
      const remaining = chatTabs.filter((tab) => tab.tabId !== tabId);
      setActiveChatTabId(remaining.length > 0 ? remaining[0].tabId : null);
    }
  };

  const handleNewTab = () => {
    if (!selectedAgentId) {
      // If no agent is selected, focus on agent list to encourage selection
      const agentList = document.querySelector('.ai-agent-list');
      if (agentList) {
        agentList.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      return;
    }

    // Find the selected agent
    const selectedAgent = agents.find(agent => agent.id === selectedAgentId);
    if (!selectedAgent) return;

    // Create a new conversation with the selected agent
    const tabId = `${selectedAgent.id}-${Date.now()}`;
    const newTab: AgentChatTab = {
      tabId,
      agentId: selectedAgent.id,
      agentName: selectedAgent.name,
      agentStatus: selectedAgent.status,
      agentIp: selectedAgent.ip,
      agentOs: selectedAgent.os,
      agentLastSeen: selectedAgent.lastSeen,
      agentCreatedAt: selectedAgent.createdAt,
      reconnectInterval: selectedAgent.reconnectInterval,
      conversationId: null, // New conversation
      contextPrompt: "",
      commandHistory: [],
      messages: [],
      isLoading: true,
      isStreaming: false,
      streamingContent: "",
      error: null,
    };

    setChatTabs((prev) => [...prev, newTab]);
    setActiveChatTabId(tabId);
    initializeAgentTab(tabId, selectedAgent);
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeChatTabId) return;

    const tab = chatTabs.find((item) => item.tabId === activeChatTabId);
    if (!tab || tab.isLoading || tab.isStreaming) return;

    const input = (tabInputs[tab.tabId] || "").trim();
    if (!input) return;

    if (!selectedModel) {
      setChatTabs((prev) =>
        prev.map((item) =>
          item.tabId === tab.tabId
            ? { ...item, error: "Select a model before starting a chat." }
            : item
        )
      );
      return;
    }

    const userMessage: ChatMessage = {
      role: "user",
      content: input,
      createdAt: new Date().toISOString(),
    };

    setChatTabs((prev) =>
      prev.map((item) =>
        item.tabId === tab.tabId
          ? {
              ...item,
              messages: [...item.messages, userMessage],
              isStreaming: true,
              streamingContent: "",
              error: null,
            }
          : item
      )
    );

    setTabInputs((prev) => ({ ...prev, [tab.tabId]: "" }));
    streamingMessageRef.current[tab.tabId] = "";

    setTimeout(() => {
      textareaRef.current?.focus();
    }, 100);

    try {
      let conversationId =
        tab.conversationId ?? conversationMap[tab.agentId] ?? null;

      // Build message history for the AI
      const historyMessages = tab.messages.concat(userMessage).map((msg) => ({
        role: msg.role,
        content: msg.content,
      }));

      const payloadMessages =
        tab.contextPrompt.trim().length > 0
          ? [{ role: "system", content: tab.contextPrompt }, ...historyMessages]
          : historyMessages;

      const requestBody: Record<string, unknown> = {
        model: selectedModel.id,
        messages: payloadMessages,
        stream: true,
        metadata: {
          agentId: tab.agentId,
          agentName: tab.agentName,
        },
      };

      if (conversationId) {
        requestBody.conversation_id = conversationId;
      }

      const response = await fetch(
        `${normalisedOpenWebUIUrl}api/chat/completions`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${jwt}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(requestBody),
        }
      );

      if (!response.ok || !response.body) {
        throw new Error(`Failed to send message: ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          const finalContent = streamingMessageRef.current[tab.tabId];
          if (finalContent && finalContent.trim().length > 0) {
            const assistantMessage: ChatMessage = {
              role: "assistant",
              content: finalContent,
              createdAt: new Date().toISOString(),
            };

            setChatTabs((prev) =>
              prev.map((item) =>
                item.tabId === tab.tabId
                  ? {
                      ...item,
                      messages: [...item.messages, assistantMessage],
                      isStreaming: false,
                      streamingContent: "",
                    }
                  : item
              )
            );
          } else {
            setChatTabs((prev) =>
              prev.map((item) =>
                item.tabId === tab.tabId
                  ? { ...item, isStreaming: false, streamingContent: "" }
                  : item
              )
            );
      }

      streamingMessageRef.current[tab.tabId] = "";
      setTimeout(() => {
        textareaRef.current?.focus();
      }, 100);
      break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const data = line.slice(6);
          if (data === "[DONE]") {
            const finalContent = streamingMessageRef.current[tab.tabId];
            const assistantMessage: ChatMessage = {
              role: "assistant",
              content: finalContent,
              createdAt: new Date().toISOString(),
            };

            if (finalContent.trim().length > 0) {
              setChatTabs((prev) =>
                prev.map((item) =>
                  item.tabId === tab.tabId
                    ? {
                        ...item,
                        messages: [...item.messages, assistantMessage],
                        isStreaming: false,
                        streamingContent: "",
                      }
                    : item
                )
              );
            } else {
              setChatTabs((prev) =>
                prev.map((item) =>
                  item.tabId === tab.tabId
                    ? { ...item, isStreaming: false, streamingContent: "" }
                    : item
                )
              );
            }

            streamingMessageRef.current[tab.tabId] = "";
            setTimeout(() => {
              textareaRef.current?.focus();
            }, 100);
            return;
          }

          try {
            const parsed = JSON.parse(data);

            const maybeConversationId = extractConversationId(parsed);
            if (maybeConversationId && maybeConversationId !== conversationId) {
              conversationId = maybeConversationId;
              setConversationMap((prev) => ({
                ...prev,
                [tab.agentId]: maybeConversationId,
              }));
              setChatTabs((prev) =>
                prev.map((item) =>
                  item.tabId === tab.tabId
                    ? { ...item, conversationId: maybeConversationId }
                    : item
                )
              );
            }

            const content = parsed.choices?.[0]?.delta?.content;
            if (content) {
              streamingMessageRef.current[tab.tabId] += content;
              const updatedContent = streamingMessageRef.current[tab.tabId];
              setChatTabs((prev) =>
                prev.map((item) =>
                  item.tabId === tab.tabId
                    ? { ...item, streamingContent: updatedContent }
                    : item
                )
              );
            }
          } catch {
            // ignore parsing errors for partial chunks
          }
        }
      }

      if (conversationId && conversationId !== tab.conversationId) {
        setConversationMap((prev) => ({
          ...prev,
          [tab.agentId]: conversationId as string,
        }));
        setChatTabs((prev) =>
          prev.map((item) =>
            item.tabId === tab.tabId
              ? { ...item, conversationId: conversationId as string }
              : item
          )
        );
      }
    } catch (err) {
      console.error("Streaming error:", err);
      const message =
        err instanceof Error ? err.message : "Failed to get response.";

      setChatTabs((prev) =>
        prev.map((item) =>
          item.tabId === tab.tabId
            ? {
                ...item,
                isStreaming: false,
                streamingContent: "",
                error: message,
                messages: [
                  ...item.messages,
                  {
                    role: "assistant",
                    content: `Error: ${message}`,
                    createdAt: new Date().toISOString(),
                  },
                ],
              }
            : item
        )
      );

      streamingMessageRef.current[tab.tabId] = "";
    }
  };

  const handleLogout = () => {
    setUrl("");
    setJwt("");
    setModels([]);
    setIsLoggedIn(false);
    setSelectedModel(null);
    setChatTabs([]);
    setActiveChatTabId(null);
    setTabInputs({});
    setConversationMap({});
    streamingMessageRef.current = {};
    setError(null);

    localStorage.removeItem("openwebui_url");
    localStorage.removeItem("openwebui_jwt");
    localStorage.removeItem("openwebui_models");
    localStorage.removeItem("openwebui_logged_in");
    localStorage.removeItem("openwebui_selected_model");
    localStorage.removeItem(CONVERSATION_STORAGE_KEY);
  };

  if (!isActive) {
    return null;
  }

  if (!isLoggedIn) {
    return (
      <div className="ai-container ai-login-container">
        <div className="ai-header">
          <div className="ai-stats">
            <SiOllama className="stats-icon" />
            <span className="stats-text">AI Assistant • Not Connected</span>
          </div>
        </div>

        <div className="ai-login-main">
          <div className="ai-login-card">
            <div className="ai-login-card-header">
              <SiOllama className="ai-login-icon" />
              <h2>Connect to Open WebUI</h2>
              <p>Enter your Open WebUI endpoint and token to start chatting with agents.</p>
            </div>

            <form className="ai-login-form" onSubmit={handleLogin}>
              <div className="form-group">
                <label htmlFor="ai-url">Open WebUI URL</label>
                <input
                  id="ai-url"
                  type="url"
                  placeholder="https://your-openwebui-instance.com/"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="ai-jwt">JWT Token</label>
                <input
                  id="ai-jwt"
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

  const activeTab = chatTabs.find((tab) => tab.tabId === activeChatTabId) || null;

  return (
    <div className="ai-container">
      <div className="ai-header">
        <div className="ai-stats">
          <SiOllama className="stats-icon" />
          <span className="stats-text">AI Assistant • Connected to Open WebUI</span>
        </div>
        <button className="logout-btn" onClick={handleLogout}>
          Logout
        </button>
      </div>
      <div className="ai-layout">
        <div className="ai-sidebar">

          <div className="model-selection">
            <h3>Select a Model</h3>
            <div className="model-dropdown">
              <select
                value={selectedModel?.id || ""}
                onChange={(e) => handleModelSelect(e.target.value)}
              >
                <option value="">Choose a model...</option>
                {models.map((model) => (
                  <option key={model.id} value={model.id}>
                    {model.name}{" "}
                    {model.provider ? `(${model.provider})` : undefined}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="ai-agent-section">
            <div className="ai-agent-header">
              <h3>Agents</h3>
              <button
                className="ai-refresh-btn"
                onClick={loadAgents}
                type="button"
                disabled={agentsLoading}
              >
                Refresh
              </button>
            </div>

            <input
              type="text"
              className="ai-agent-search"
              placeholder="Search by name, ID, or IP..."
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
            />

            {agentsError && (
              <div className="error-message">{agentsError}</div>
            )}

            <div className="ai-agent-list">
              {agentsLoading && filteredAgents.length === 0 ? (
                <div className="ai-agent-empty">Loading agents...</div>
              ) : filteredAgents.length === 0 ? (
                <div className="ai-agent-empty">No agents found.</div>
              ) : (
                filteredAgents.map((agent) => {
                  const isActiveTab = activeTab?.agentId === agent.id;
                  return (
                    <button
                      key={agent.id}
                      type="button"
                      className={`ai-agent-item ${
                        selectedAgentId === agent.id ? "active" : ""
                      }`}
                      onClick={() => {
                        setSelectedAgentId(agent.id);
                        handleOpenAgentTab(agent);
                      }}
                    >
                      <div className="ai-agent-item-header">
                        <span className="ai-agent-name">{agent.name}</span>
                        <span className="ai-agent-last-seen">{formatLastSeen(agent.lastSeen)}</span>
                      </div>
                      <div className="ai-agent-meta">
                        <span>{agent.ip}</span>
                        <span>{agent.os}</span>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>
        </div>

        <div className="ai-chat-area">
          {chatTabs.length === 0 ? (
            <div className="ai-chat-empty">
              Select an agent to start a conversation.
            </div>
          ) : (
            <>
              <div className="ai-chat-tabs">
                {chatTabs.map((tab) => (
                  <button
                    key={tab.tabId}
                    type="button"
                    className={`ai-chat-tab ${
                      tab.tabId === activeChatTabId ? "active" : ""
                    }`}
                    onClick={() => setActiveChatTabId(tab.tabId)}
                  >
                    <span className="ai-chat-tab-name">{tab.agentName}</span>
                    <span
                      className="ai-chat-tab-close"
                      onClick={(event) => {
                        event.stopPropagation();
                        handleCloseTab(tab.tabId);
                      }}
                    >
                      ×
                    </span>
                  </button>
                ))}
                <button
                  className="ai-chat-tab-new"
                  onClick={handleNewTab}
                  title="New Chat Tab"
                >
                  +
                </button>
              </div>

              {activeTab ? (
                <div className="chat-interface">
                  <div className="chat-header">
                    <div className="chat-model-info">
                      <span>
                        {activeTab.agentName} ({calculateStatus(activeTab.agentLastSeen, activeTab.reconnectInterval)})
                      </span>
                      <span>
                        Model: {selectedModel?.name || "None selected"}
                      </span>
                      <span>
                        IP {activeTab.agentIp} • {activeTab.agentOs} • Last seen{" "}
                        {formatTimestamp(activeTab.agentLastSeen)}
                      </span>
                    </div>
                    <div className="chat-controls">
                    </div>
                  </div>

                  {activeTab.error && (
                    <div className="error-message">{activeTab.error}</div>
                  )}

                  <div className="chat-messages">
                    {activeTab.isLoading ? (
                      <div className="ai-chat-empty">Loading context...</div>
                    ) : activeTab.messages.length === 0 &&
                      !activeTab.isStreaming ? (
                      <div className="chat-welcome">
                        <p>
                          Ask about this agent&apos;s command history or status.
                        </p>
                      </div>
                    ) : (
                      <>
                        {activeTab.messages.map((message) => {
                          const isCommandMessage = isCommandOutputMessage(message);
                          return (
                            <div
                              key={message.createdAt ?? Math.random().toString()}
                              className={`message ${message.role}`}
                            >
                              <div className="message-icon">
                                {message.role === "user" ? (
                                  <FaUserSecret className="user-icon" />
                                ) : (
                                  <SiOllama className="bot-icon" />
                                )}
                              </div>
                              <div
                                className={`message-content${
                                  isCommandMessage ? " command-output" : ""
                                }`}
                              >
                                {renderMessageContent(message)}
                              </div>
                            </div>
                          );
                        })}

                        {activeTab.isStreaming && (
                          <div className="message assistant">
                            <div className="message-icon">
                              <SiOllama className="bot-icon" />
                            </div>
                            <div className="message-content streaming">
                              {renderMessageContent({
                                role: "assistant",
                                content: activeTab.streamingContent || "",
                              })}
                              <span className="streaming-cursor">|</span>
                            </div>
                          </div>
                        )}

                        <div ref={messagesEndRef} />
                      </>
                    )}
                  </div>

                  <form className="chat-input-form" onSubmit={handleSendMessage}>
                    <div className="chat-input-container">
                      <textarea
                        ref={textareaRef}
                        value={tabInputs[activeTab.tabId] || ""}
                        onChange={(e) =>
                          setTabInputs((prev) => ({
                            ...prev,
                            [activeTab.tabId]: e.target.value,
                          }))
                        }
                        placeholder={
                          activeTab.isStreaming
                            ? "AI is responding..."
                            : selectedModel
                            ? "Type your message..."
                            : "Select a model to start chatting..."
                        }
                        className="chat-input"
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && !e.shiftKey) {
                            e.preventDefault();
                            handleSendMessage(e);
                          }
                        }}
                        disabled={
                          activeTab.isStreaming ||
                          activeTab.isLoading ||
                          !selectedModel
                        }
                      />
                      <button
                        type="submit"
                        className="send-btn"
                        disabled={
                          activeTab.isStreaming ||
                          activeTab.isLoading ||
                          !selectedModel ||
                          !(tabInputs[activeTab.tabId] || "").trim()
                        }
                      >
                        <IoSend />
                      </button>
                    </div>
                  </form>
                </div>
              ) : (
                <div className="ai-chat-empty">
                  Select a tab to continue chatting.
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
