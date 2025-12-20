import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { useWebSocket, Agent, Command, AgentHandler } from "./useWebSocket";

type RunStatus = "idle" | "running" | "completed" | "stopped" | "error";

type StepStatus = "pending" | "running" | "completed" | "blocked" | "error";
type StepKind = "command" | "info" | "thought" | "completion"; // Phase 2: Add completion kind

export interface AutonomyStep {
  id: string;
  kind: StepKind;
  title: string;
  status: StepStatus;
  commandId?: number;
  commandText?: string;
  output?: string;
  detail?: string;
  timestamp: number;
}

export interface AutonomyRunOptions {
  agent: Agent;
  goal: string;
  model: { id: string; name?: string };
  apiBaseUrl: string;
  apiKey?: string;
  maxSteps?: number;
  useAllowlist?: boolean;
  timeoutMs?: number;
}

type ChatRole = "system" | "user" | "assistant" | "tool";

interface ChatMessage {
  role: ChatRole;
  content: string;
  name?: string;
  tool_call_id?: string;
  tool_calls?: {
    id: string;
    type: "function";
    function: {
      name: string;
      arguments: string;
    };
  }[];
}

interface ToolResult {
  status: "ok" | "error" | "blocked" | "timeout";
  message: string;
  data?: Record<string, unknown>;
}

// Phase 1: Command manifest interfaces
interface ExecutedCommand {
  id: string;
  command: string;
  normalizedCommand: string;
  timestamp: number;
  completedAt?: number;
  status: "pending" | "ok" | "error" | "timeout" | "blocked";
  outputPreview: string;
  outputLength: number;
  errorMessage?: string;
}

interface LoopDetectionResult {
  isLoop: boolean;
  occurrences: number;
  action: "allow" | "warn" | "block";
  message?: string;
}

// Phase 3: Critical findings types
type CriticalFindingCategory =
  | "credential"
  | "private_key"
  | "ip_address"
  | "hostname"
  | "username"
  | "vulnerability"
  | "service"
  | "path"
  | "other";

interface CriticalFinding {
  id: string;
  category: CriticalFindingCategory;
  value: string;
  context: string;
  timestamp: number;
  confidence: "high" | "medium" | "low";
}

interface PatternDefinition {
  pattern: RegExp;
  category: CriticalFindingCategory;
  confidence: "high" | "medium" | "low";
  description: string;
}

interface ThoughtUnit {
  assistantMessage: ChatMessage;
  toolResults: ChatMessage[];
}

// Phase 4: Progress tracking types
interface PhaseProgress {
  phaseNumber: number;
  phaseName: string;
  completedAt: number;
  osDetected?: "linux" | "windows" | "macos" | "unknown";
  keyFindings: string[];
  blockers: string[];
}

const DEFAULT_MAX_STEPS = 25; // Phase 4: Increased from 8 to support phased triage
const DEFAULT_TIMEOUT_MS = 120000;
const TOKEN_CHAR_RATIO = 4; // Rough heuristic: 4 chars ~ 1 token
const CONTEXT_TOKEN_BUDGET = 16000; // Assume 16k token context
const CONTEXT_TOKEN_THRESHOLD = 12000; // Trigger summarization when estimated > this
const CONTEXT_CHAR_THRESHOLD = CONTEXT_TOKEN_THRESHOLD * TOKEN_CHAR_RATIO;
const SUMMARY_MAX_CHARS = 3200; // ~800 tokens
const SUMMARY_INPUT_LIMIT_CHARS = 8000; // cap what we feed to the summarizer
const SUMMARIZE_MIN_ACTIONS = 4; // minimum tool calls between summaries
const KEEP_RECENT_MESSAGES = 4; // keep last few raw steps verbatim

// Phase 1: Loop detection constants
const LOOP_WARN_THRESHOLD = 1; // Warn after 1 prior occurrence
const LOOP_BLOCK_THRESHOLD = 2; // Block after 2 prior occurrences
const MAX_COMMANDS_IN_SYSTEM_PROMPT = 20; // Show last 20 commands in system prompt
const MAX_COMMAND_DISPLAY_LENGTH = 500; // Truncate very long commands for display
const OUTPUT_PREVIEW_LENGTH = 300; // First 300 chars of output

// Phase 3: Context management constants
const KEEP_RECENT_UNITS = 2; // Keep last 2 complete thought units
const MAX_FINDINGS_IN_PROMPT = 50; // Limit total findings in system prompt
const MAX_FINDINGS_PER_CATEGORY = 10; // Limit per category
const FINDING_VALUE_MAX_LENGTH = 200; // Truncate very long finding values

// Phase 3: Pattern definitions for critical findings extraction (OS agnostic)
const CRITICAL_PATTERNS: PatternDefinition[] = [
  // === CREDENTIALS (OS agnostic) ===
  {
    pattern: /password[=:]\s*["']?([^\s"']+)/gi,
    category: "credential",
    confidence: "high",
    description: "Password assignment",
  },
  {
    pattern: /api[_-]?key[=:]\s*["']?([^\s"']+)/gi,
    category: "credential",
    confidence: "high",
    description: "API key",
  },
  {
    pattern: /secret[=:]\s*["']?([^\s"']+)/gi,
    category: "credential",
    confidence: "high",
    description: "Secret value",
  },
  {
    pattern: /token[=:]\s*["']?([^\s"']+)/gi,
    category: "credential",
    confidence: "medium",
    description: "Token value",
  },
  {
    pattern: /pwd[=:]\s*["']?([^\s"']+)/gi,
    category: "credential",
    confidence: "medium",
    description: "Password (pwd) assignment",
  },

  // === PRIVATE KEYS (OS agnostic) ===
  {
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/gi,
    category: "private_key",
    confidence: "high",
    description: "Private key header",
  },
  {
    pattern: /id_rsa|id_ed25519|id_ecdsa|id_dsa/gi,
    category: "private_key",
    confidence: "high",
    description: "SSH key file reference",
  },
  {
    pattern: /\.pem|\.key|\.p12|\.pfx|\.ppk/gi,
    category: "private_key",
    confidence: "medium",
    description: "Key file extension",
  },

  // === IP ADDRESSES (OS agnostic) ===
  {
    pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
    category: "ip_address",
    confidence: "high",
    description: "Private IP (10.x.x.x)",
  },
  {
    pattern: /\b(192\.168\.\d{1,3}\.\d{1,3})\b/g,
    category: "ip_address",
    confidence: "high",
    description: "Private IP (192.168.x.x)",
  },
  {
    pattern: /\b(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
    category: "ip_address",
    confidence: "high",
    description: "Private IP (172.16-31.x.x)",
  },

  // === PRIVILEGED USERS - Linux/macOS ===
  {
    pattern: /\b(root)\b/gi,
    category: "username",
    confidence: "high",
    description: "Root user (Linux/macOS)",
  },
  {
    pattern: /uid=0|gid=0/gi,
    category: "username",
    confidence: "high",
    description: "Root UID/GID (Linux/macOS)",
  },
  {
    pattern: /\b(wheel|sudo)\s+group/gi,
    category: "username",
    confidence: "medium",
    description: "Sudo/wheel group membership",
  },

  // === PRIVILEGED USERS - Windows ===
  {
    pattern: /\b(Administrator|SYSTEM)\b/g,
    category: "username",
    confidence: "high",
    description: "Windows privileged user",
  },
  {
    pattern: /NT AUTHORITY\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)/gi,
    category: "username",
    confidence: "high",
    description: "Windows NT AUTHORITY account",
  },
  {
    pattern: /BUILTIN\\Administrators/gi,
    category: "username",
    confidence: "high",
    description: "Windows Administrators group",
  },
  {
    pattern: /Domain Admins|Enterprise Admins/gi,
    category: "username",
    confidence: "high",
    description: "Windows domain admin groups",
  },

  // === VULNERABILITIES (OS agnostic) ===
  {
    pattern: /CVE-\d{4}-\d{4,}/gi,
    category: "vulnerability",
    confidence: "high",
    description: "CVE reference",
  },
  {
    pattern: /MS\d{2}-\d{3}/gi,
    category: "vulnerability",
    confidence: "high",
    description: "Microsoft Security Bulletin",
  },

  // === SERVICES/PORTS (OS agnostic) ===
  {
    pattern: /(\d{1,5})\/(tcp|udp)\s+open\s+(\w+)/gi,
    category: "service",
    confidence: "medium",
    description: "Open port/service (nmap format)",
  },
  {
    pattern: /LISTEN(ING)?\s+.*[:\s](\d{1,5})/gi,
    category: "service",
    confidence: "medium",
    description: "Listening port",
  },
  {
    pattern: /\b(22|23|25|53|80|443|445|3389|5985|5986)\b.*\b(open|listen)/gi,
    category: "service",
    confidence: "medium",
    description: "Common service ports",
  },

  // === SENSITIVE PATHS - Linux/macOS ===
  {
    pattern: /\/etc\/(passwd|shadow|sudoers|ssh|hosts)/gi,
    category: "path",
    confidence: "medium",
    description: "Linux sensitive config file",
  },
  {
    pattern: /\.ssh\/|authorized_keys|known_hosts|id_rsa/gi,
    category: "path",
    confidence: "medium",
    description: "SSH directory/files",
  },
  {
    pattern: /\/var\/log\/(auth|secure|syslog)/gi,
    category: "path",
    confidence: "medium",
    description: "Linux log files",
  },

  // === SENSITIVE PATHS - Windows ===
  {
    pattern: /C:\\Windows\\System32\\config\\(SAM|SYSTEM|SECURITY)/gi,
    category: "path",
    confidence: "high",
    description: "Windows SAM/registry hives",
  },
  {
    pattern: /C:\\Users\\[^\\]+\\(AppData|Desktop|Documents)/gi,
    category: "path",
    confidence: "medium",
    description: "Windows user directories",
  },
  {
    pattern: /\\\.ssh\\|\\id_rsa|\\\.aws\\credentials/gi,
    category: "path",
    confidence: "high",
    description: "Windows SSH/credential files",
  },
  {
    pattern: /unattend\.xml|sysprep\.xml/gi,
    category: "path",
    confidence: "high",
    description: "Windows unattend files (may contain creds)",
  },
  {
    pattern: /web\.config|app\.config|appsettings\.json/gi,
    category: "path",
    confidence: "medium",
    description: "Application config files",
  },

  // === HOSTNAMES (OS agnostic) ===
  {
    pattern: /\b([a-zA-Z0-9-]+\.(local|internal|corp|lan|domain))\b/gi,
    category: "hostname",
    confidence: "medium",
    description: "Internal hostname",
  },
  {
    pattern: /\\\\([a-zA-Z0-9-]+)\\/g,
    category: "hostname",
    confidence: "high",
    description: "Windows UNC path hostname",
  },
];

// Phase 3: Structured summary prompt
const STRUCTURED_SUMMARY_PROMPT = `Summarize the following C2 agent session history. Structure your response EXACTLY as follows:

## Commands Executed
For each command, write: "[STATUS] command" where STATUS is SUCCESS, FAILED, or PARTIAL
Example:
- [SUCCESS] whoami
- [FAILED] cat /etc/shadow (permission denied)

## Key Discoveries
List important findings that haven't been captured in the Critical Findings section:
- Usernames found
- Services identified
- File system observations
- Access levels determined

## Current State
In 1-2 sentences, describe:
- What has been accomplished
- What the agent's current access/position is

## Remaining Questions
List what still needs to be determined to complete the goal.

IMPORTANT:
- Do NOT include raw JSON or tool call syntax
- Do NOT repeat information that's in the Command Manifest or Critical Findings sections
- Be concise but preserve actionable details
- Maximum 500 tokens`;

const toolDefinitions = [
  {
    name: "run_command",
    description:
      "Queue and execute a command on the selected agent. Always include the full command with arguments.",
    parameters: {
      type: "object",
      properties: {
        command: {
          type: "string",
          description: "Full command to execute on the target agent.",
        },
      },
      required: ["command"],
    },
  },
  {
    name: "get_file",
    description:
      "Download a file from the target by issuing a get command. Path should be absolute or relative to the current working directory.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the file to retrieve from the target host.",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "get_recent_commands",
    description:
      "Retrieve the latest commands executed on this agent with status and output summaries.",
    parameters: {
      type: "object",
      properties: {
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 20,
          default: 5,
        },
      },
    },
  },
  {
    name: "get_executed_commands",
    description:
      "Get the complete list of commands executed in this session. Use this to review what has already been run and see output summaries. More detailed than the list in the system prompt.",
    parameters: {
      type: "object",
      properties: {
        filter_status: {
          type: "string",
          enum: ["all", "ok", "error", "pending"],
          description: "Filter by status. Default: all",
        },
        include_output: {
          type: "boolean",
          description: "Include output previews (first 300 chars). Default: true",
        },
      },
    },
  },
  {
    name: "complete_task",
    description:
      "Signal that the task is complete or cannot proceed further. You MUST call this tool when finished - do not simply stop responding. Provide a structured summary of what was accomplished.",
    parameters: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["completed", "partial", "blocked", "failed"],
          description:
            "Outcome status: 'completed' (goal fully achieved), 'partial' (some progress made), 'blocked' (waiting on external factor), 'failed' (cannot proceed)",
        },
        summary: {
          type: "string",
          description: "Brief summary of what was accomplished (2-3 sentences)",
        },
        findings: {
          type: "array",
          items: { type: "string" },
          description: "Key findings, discoveries, or artifacts collected",
        },
        recommendations: {
          type: "array",
          items: { type: "string" },
          description: "Recommended next steps for the operator",
        },
        risk_assessment: {
          type: "object",
          properties: {
            high: {
              type: "array",
              items: { type: "string" },
              description: "High-priority risks or vulnerabilities found",
            },
            medium: {
              type: "array",
              items: { type: "string" },
              description: "Medium-priority items",
            },
            low: {
              type: "array",
              items: { type: "string" },
              description: "Low-priority or informational items",
            },
          },
          description: "Categorized risk assessment (optional)",
        },
      },
      required: ["status", "summary"],
    },
  },
  {
    name: "get_critical_findings",
    description:
      "Get the list of critical findings (credentials, IPs, keys, vulnerabilities, etc.) extracted from command outputs during this session. Use this to reference discovered values.",
    parameters: {
      type: "object",
      properties: {
        category: {
          type: "string",
          enum: [
            "all",
            "credential",
            "private_key",
            "ip_address",
            "hostname",
            "username",
            "vulnerability",
            "service",
            "path",
          ],
          description: "Filter by category. Default: all",
        },
      },
    },
  },
  {
    name: "report_progress",
    description:
      "Report progress on the current phase. Call this after completing each phase to checkpoint your findings. This helps track progress even if context is summarized.",
    parameters: {
      type: "object",
      properties: {
        current_phase: {
          type: "string",
          description:
            "Name of the phase just completed (e.g., 'System Identification', 'User Enumeration')",
        },
        phase_number: {
          type: "integer",
          minimum: 1,
          maximum: 6,
          description: "Phase number (1-6)",
        },
        os_detected: {
          type: "string",
          enum: ["linux", "windows", "macos", "unknown"],
          description:
            "Operating system detected (set in Phase 1, include in subsequent calls)",
        },
        key_findings: {
          type: "array",
          items: { type: "string" },
          description: "Important findings from this phase",
        },
        blockers: {
          type: "array",
          items: { type: "string" },
          description:
            "Issues encountered (permission denied, command not found, etc.)",
        },
        next_phase: {
          type: "string",
          description: "What you plan to do next",
        },
      },
      required: ["current_phase", "phase_number"],
    },
  },
] as const;

const buildToolList = () =>
  toolDefinitions.map((tool) => ({
    type: "function",
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
    },
  }));

const normalizeBaseUrl = (url: string) => url.replace(/\/+$/, "");

const findHandlerForAgent = (
  handlers: AgentHandler[],
  agent: Agent
): AgentHandler | undefined =>
  handlers.find(
    (handler) =>
      handler.agentHttpHeaderId === agent.handlerId ||
      handler.agentName === agent.handlerName
  );

const extractVerb = (command: string) => {
  const tokens = command.trim().split(/\s+/);
  if (tokens[0]?.toLowerCase() === "exec" && tokens[1]) {
    return tokens[1].toLowerCase();
  }
  return tokens[0]?.toLowerCase() || "";
};

const estimateTokensFromMessages = (messages: ChatMessage[]) => {
  const totalChars = messages.reduce((sum, msg) => {
    if (typeof msg.content === "string") {
      return sum + msg.content.length;
    }
    return sum;
  }, 0);
  return Math.ceil(totalChars / TOKEN_CHAR_RATIO);
};

// Phase 1: Command normalization for duplicate detection
const normalizeCommand = (cmd: string): string => {
  return cmd
    .toLowerCase()
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/\s*([|&;><])\s*/g, '$1');
};

// Phase 1: Truncate long commands for display
const truncateCommandForDisplay = (cmd: string): string => {
  if (cmd.length <= MAX_COMMAND_DISPLAY_LENGTH) return cmd;
  return cmd.slice(0, MAX_COMMAND_DISPLAY_LENGTH) + "... (truncated)";
};

// Phase 3: Extract critical findings from command output
const extractCriticalFindings = (
  output: string,
  commandContext: string
): CriticalFinding[] => {
  const findings: CriticalFinding[] = [];
  const seen = new Set<string>(); // Dedupe within this extraction

  for (const { pattern, category, confidence } of CRITICAL_PATTERNS) {
    // Reset regex state for global patterns
    pattern.lastIndex = 0;

    let match;
    while ((match = pattern.exec(output)) !== null) {
      // Use the captured group if available, otherwise full match
      const value = match[1] || match[0];
      const dedupeKey = `${category}:${value.toLowerCase()}`;

      if (!seen.has(dedupeKey)) {
        seen.add(dedupeKey);
        findings.push({
          id: `finding-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          category,
          value: value.slice(0, FINDING_VALUE_MAX_LENGTH),
          context: commandContext,
          timestamp: Date.now(),
          confidence,
        });
      }
    }
  }

  return findings;
};

// Phase 3: Extract recent complete thought units
const extractRecentThoughtUnits = (
  messages: ChatMessage[],
  maxUnits: number = KEEP_RECENT_UNITS
): ChatMessage[] => {
  const units: ThoughtUnit[] = [];
  let currentToolResults: ChatMessage[] = [];

  // Walk backwards through messages (skip system + goal at 0, 1)
  for (let i = messages.length - 1; i >= 2; i--) {
    const msg = messages[i];

    if (msg.role === "tool") {
      currentToolResults.unshift(msg);
    } else if (msg.role === "assistant") {
      // Found an assistant message - this completes a unit
      units.unshift({
        assistantMessage: msg,
        toolResults: [...currentToolResults],
      });
      currentToolResults = [];

      if (units.length >= maxUnits) {
        break;
      }
    }
  }

  // Flatten units back to message array
  const result: ChatMessage[] = [];
  for (const unit of units) {
    result.push(unit.assistantMessage);
    result.push(...unit.toolResults);
  }

  return result;
};

// Phase 1 + Phase 3 + Phase 4: Build system prompt with command history, critical findings, and phase progress
const buildSystemPromptWithHistory = (
  basePrompt: string,
  executedCommands: ExecutedCommand[],
  criticalFindings: CriticalFinding[] = [],
  phaseProgress: PhaseProgress[] = []
): string => {
  const parts = [basePrompt];

  if (executedCommands.length > 0) {
    parts.push("");
    parts.push("## Commands Already Executed This Session");
    parts.push("DO NOT repeat these commands. Use get_executed_commands to see their outputs.");
    parts.push("");

    const recentCommands = executedCommands.slice(-MAX_COMMANDS_IN_SYSTEM_PROMPT);
    const olderCount = executedCommands.length - recentCommands.length;

    if (olderCount > 0) {
      parts.push(`(${olderCount} older commands omitted - use get_executed_commands to see all)`);
      parts.push("");
    }

    recentCommands.forEach((cmd, i) => {
      const num = olderCount + i + 1;
      const statusIcon = cmd.status === "ok" ? "✓" : cmd.status === "error" ? "✗" : "⏳";
      const displayCmd = truncateCommandForDisplay(cmd.command);
      parts.push(`${num}. [${statusIcon}] ${displayCmd}`);
    });
  }

  // Phase 3: Add critical findings section
  if (criticalFindings.length > 0) {
    parts.push("");
    parts.push("## Critical Findings Discovered");
    parts.push("These values were extracted from command outputs. Reference them as needed:");
    parts.push("");

    // Group by category
    const grouped = new Map<CriticalFindingCategory, CriticalFinding[]>();
    for (const finding of criticalFindings) {
      const list = grouped.get(finding.category) || [];
      list.push(finding);
      grouped.set(finding.category, list);
    }

    // Track total findings added to respect MAX_FINDINGS_IN_PROMPT
    let totalAdded = 0;

    // Show high confidence first, limit per category
    for (const [category, findings] of grouped) {
      if (totalAdded >= MAX_FINDINGS_IN_PROMPT) break;

      const sorted = findings
        .sort((a, b) => {
          const confOrder = { high: 0, medium: 1, low: 2 };
          return confOrder[a.confidence] - confOrder[b.confidence];
        })
        .slice(0, MAX_FINDINGS_PER_CATEGORY);

      const categoryName = category.toUpperCase().replace(/_/g, " ");
      parts.push(`### ${categoryName}`);
      for (const f of sorted) {
        if (totalAdded >= MAX_FINDINGS_IN_PROMPT) break;
        parts.push(`- ${f.value} (from: ${f.context})`);
        totalAdded++;
      }
    }

    if (criticalFindings.length > totalAdded) {
      parts.push("");
      parts.push(`(${criticalFindings.length - totalAdded} more findings - use get_critical_findings to see all)`);
    }
  }

  // Phase 4: Add phase progress section
  if (phaseProgress.length > 0) {
    parts.push("");
    parts.push("## Phase Progress");

    const latestOS = phaseProgress.find((p) => p.osDetected)?.osDetected;
    if (latestOS) {
      parts.push(`Detected OS: ${latestOS.toUpperCase()}`);
    }

    parts.push(`Completed phases: ${phaseProgress.length}/6`);
    parts.push("");

    for (const phase of phaseProgress) {
      parts.push(`✓ Phase ${phase.phaseNumber}: ${phase.phaseName}`);
      if (phase.keyFindings.length > 0) {
        parts.push(
          `  Findings: ${phase.keyFindings.slice(0, 3).join(", ")}${
            phase.keyFindings.length > 3 ? "..." : ""
          }`
        );
      }
    }

    const nextPhase = phaseProgress.length + 1;
    if (nextPhase <= 6) {
      const phaseNames = [
        "System Identification",
        "User & Access Enumeration",
        "Network Reconnaissance",
        "Process & Service Inventory",
        "Filesystem Reconnaissance",
        "Compile Final Report",
      ];
      parts.push("");
      parts.push(`→ Next: Phase ${nextPhase} - ${phaseNames[nextPhase - 1]}`);
    }
  }

  return parts.join("\n");
};

export function useAutonomyRunner() {
  const { user } = useAuth();
  const { sendCommand, commands, handlers } = useWebSocket(true);

  const [status, setStatus] = useState<RunStatus>("idle");
  const [steps, setSteps] = useState<AutonomyStep[]>([]);
  const [error, setError] = useState<string | null>(null);

  const commandsRef = useRef<{ [agentId: string]: Command[] }>({});
  const stopRequestedRef = useRef(false);
  const runIdRef = useRef<string | null>(null);
  const executedCommandsRef = useRef<ExecutedCommand[]>([]); // Phase 1: Command manifest
  const criticalFindingsRef = useRef<CriticalFinding[]>([]); // Phase 3: Critical findings
  const phaseProgressRef = useRef<PhaseProgress[]>([]); // Phase 4: Phase progress tracking

  useEffect(() => {
    commandsRef.current = commands;
  }, [commands]);

  useEffect(
    () => () => {
      stopRequestedRef.current = true;
      runIdRef.current = null;
    },
    []
  );

  const waitForCommandResult = useCallback(
    async (
      agentId: string,
      commandText: string,
      username: string,
      anchorId: number,
      timeoutMs: number
    ): Promise<Command> => {
      const start = Date.now();
      let trackedId: number | null = null;

      return new Promise<Command>((resolve, reject) => {
        const interval = setInterval(() => {
          const agentCommands = commandsRef.current[agentId] || [];
          const candidates = agentCommands.filter(
            (cmd) =>
              cmd.id > anchorId &&
              cmd.command === commandText &&
              cmd.clientUsername === username
          );

          if (candidates.length > 0) {
            const latest = candidates[candidates.length - 1];
            trackedId = trackedId ?? latest.id;

            if (
              latest.status === "completed" ||
              latest.status === "error" ||
              (latest.output ?? "").trim().length > 0
            ) {
              clearInterval(interval);
              resolve(latest);
              return;
            }
          }

          if (Date.now() - start > timeoutMs) {
            clearInterval(interval);
            reject(new Error("Command timed out while waiting for output."));
          }
        }, 500);
      });
    },
    []
  );

  const appendStep = useCallback((step: AutonomyStep) => {
    setSteps((prev) => [...prev, step]);
  }, []);

  const updateStep = useCallback(
    (id: string, updater: (step: AutonomyStep) => AutonomyStep) => {
      setSteps((prev) => prev.map((step) => (step.id === id ? updater(step) : step)));
    },
    []
  );

  // Phase 1: Loop detection function
  const detectLoop = useCallback((command: string): LoopDetectionResult => {
    // Defensive check
    if (!Array.isArray(executedCommandsRef.current)) {
      console.error("Command manifest corrupted, resetting");
      executedCommandsRef.current = [];
      return { isLoop: false, occurrences: 0, action: "allow" };
    }

    const normalized = normalizeCommand(command);
    const priorExecutions = executedCommandsRef.current.filter(
      (c) => c.normalizedCommand === normalized
    );
    const occurrences = priorExecutions.length;

    if (occurrences >= LOOP_BLOCK_THRESHOLD) {
      return {
        isLoop: true,
        occurrences,
        action: "block",
        message: `Command "${command}" has already been executed ${occurrences} times. This appears to be a loop. Try a different approach or call complete_task if you are stuck.`,
      };
    }

    if (occurrences >= LOOP_WARN_THRESHOLD) {
      return {
        isLoop: true,
        occurrences,
        action: "warn",
        message: `Warning: Command "${command}" was already executed. Output from previous execution: "${priorExecutions[0]?.outputPreview || 'N/A'}". If you need this data, use get_executed_commands instead of re-running.`,
      };
    }

    return { isLoop: false, occurrences: 0, action: "allow" };
  }, []);

  // Phase 1: get_executed_commands tool handler
  const executeGetExecutedCommands = useCallback(
    async (args: { filter_status?: string; include_output?: boolean }): Promise<ToolResult> => {
      const filterStatus = args.filter_status || "all";
      const includeOutput = args.include_output !== false;

      let commands = [...executedCommandsRef.current];

      if (filterStatus !== "all") {
        commands = commands.filter((c) => c.status === filterStatus);
      }

      const formatted = commands.map((cmd, i) => {
        const lines = [
          `${i + 1}. [${cmd.status.toUpperCase()}] ${cmd.command}`,
          `   Executed: ${new Date(cmd.timestamp).toISOString()}`,
        ];

        if (cmd.completedAt) {
          const duration = cmd.completedAt - cmd.timestamp;
          lines.push(`   Duration: ${duration}ms`);
        }

        if (includeOutput && cmd.outputPreview) {
          lines.push(
            `   Output (${cmd.outputLength} chars): ${cmd.outputPreview}${
              cmd.outputLength > OUTPUT_PREVIEW_LENGTH ? "..." : ""
            }`
          );
        }

        if (cmd.errorMessage) {
          lines.push(`   Error: ${cmd.errorMessage}`);
        }

        return lines.join("\n");
      });

      const stepId = `info-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      appendStep({
        id: stepId,
        kind: "info",
        title: `Retrieved ${commands.length} executed command(s)`,
        status: "completed",
        detail: formatted.join("\n\n"),
        timestamp: Date.now(),
      });

      return {
        status: "ok",
        message: `Found ${commands.length} commands`,
        data: {
          total: executedCommandsRef.current.length,
          filtered: commands.length,
          commands: commands.map((c) => ({
            command: c.command,
            status: c.status,
            timestamp: c.timestamp,
            outputPreview: includeOutput ? c.outputPreview : undefined,
            outputLength: c.outputLength,
          })),
        },
      };
    },
    [appendStep]
  );

  const executeRunCommand = useCallback(
    async (
      args: { command?: string },
      agent: Agent,
      allowed: string[] | null,
      runId: string,
      timeoutMs: number,
      modelName?: string
    ): Promise<ToolResult> => {
      const commandText = (args.command || "").trim();
      if (!commandText) {
        return { status: "error", message: "Command text missing." };
      }

      // Phase 1: Loop detection - check BEFORE allowlist
      const loopCheck = detectLoop(commandText);

      if (loopCheck.action === "block") {
        appendStep({
          id: `blocked-${Date.now()}`,
          kind: "info",
          title: `Blocked: Duplicate command`,
          detail: loopCheck.message,
          status: "blocked",
          timestamp: Date.now(),
        });

        return {
          status: "blocked",
          message: loopCheck.message!,
          data: { loopDetected: true, occurrences: loopCheck.occurrences },
        };
      }

      const verb = extractVerb(commandText);
      const allowlistEnabled = Array.isArray(allowed) && allowed.length > 0;
      if (allowlistEnabled && !allowed.includes(verb)) {
        return {
          status: "blocked",
          message: `Command '${verb}' is not in the allowed list.`,
        };
      }

      const username = `${user?.username || "operator"} via ${modelName || "autonomy"}`;
      const anchorId = (commandsRef.current[agent.id] || []).reduce(
        (max, cmd) => (cmd.id > max ? cmd.id : max),
        0
      );

      const stepId = `cmd-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

      // Phase 1: Add to manifest as pending
      const executionId = `exec-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const normalizedCmd = normalizeCommand(commandText);

      executedCommandsRef.current.push({
        id: executionId,
        command: commandText,
        normalizedCommand: normalizedCmd,
        timestamp: Date.now(),
        status: "pending",
        outputPreview: "",
        outputLength: 0,
      });

      appendStep({
        id: stepId,
        kind: "command",
        title: commandText,
        commandText,
        status: "running",
        timestamp: Date.now(),
      });

      sendCommand(agent.id, commandText, username);

      try {
        const result = await waitForCommandResult(
          agent.id,
          commandText,
          username,
          anchorId,
          timeoutMs
        );

        if (runIdRef.current !== runId) {
          return { status: "error", message: "Run cancelled." };
        }

        // Phase 1: Update manifest entry with result
        const entryIndex = executedCommandsRef.current.findIndex((c) => c.id === executionId);
        if (entryIndex !== -1) {
          executedCommandsRef.current[entryIndex] = {
            ...executedCommandsRef.current[entryIndex],
            completedAt: Date.now(),
            status: result.status === "completed" ? "ok" : "error",
            outputPreview: (result.output || "").slice(0, OUTPUT_PREVIEW_LENGTH),
            outputLength: (result.output || "").length,
            errorMessage: result.status !== "completed" ? result.output : undefined,
          };
        }

        // Phase 3: Extract critical findings from command output
        if (result.output) {
          const newFindings = extractCriticalFindings(result.output, commandText);
          if (newFindings.length > 0) {
            // Dedupe against existing findings
            for (const finding of newFindings) {
              const exists = criticalFindingsRef.current.some(
                (existing) =>
                  existing.category === finding.category &&
                  existing.value.toLowerCase() === finding.value.toLowerCase()
              );
              if (!exists) {
                criticalFindingsRef.current.push(finding);
              }
            }
          }
        }

        updateStep(stepId, (step) => ({
          ...step,
          commandId: result.id,
          output: (result.output || "").trim(),
          status: result.status === "completed" ? "completed" : "error",
        }));

        // Phase 1: Include warning if this was a duplicate
        const baseMessage = `Command ${result.status}`;
        const message =
          loopCheck.action === "warn"
            ? `${loopCheck.message}\n\nNew output: ${(result.output || "").trim()}`
            : baseMessage;

        return {
          status: result.status === "completed" ? "ok" : "error",
          message,
          data: {
            commandId: result.id,
            status: result.status,
            output: result.output,
          },
        };
      } catch (err) {
        // Phase 1: Update manifest with error
        const entryIndex = executedCommandsRef.current.findIndex((c) => c.id === executionId);
        if (entryIndex !== -1) {
          executedCommandsRef.current[entryIndex].status = "error";
          executedCommandsRef.current[entryIndex].errorMessage =
            err instanceof Error ? err.message : "Unknown error";
          executedCommandsRef.current[entryIndex].completedAt = Date.now();
        }

        updateStep(stepId, (step) => ({
          ...step,
          status: "error",
          detail: err instanceof Error ? err.message : "Unknown error",
        }));

        return {
          status: "error",
          message: err instanceof Error ? err.message : "Command failed",
        };
      }
    },
    [appendStep, sendCommand, updateStep, user?.username, waitForCommandResult, detectLoop]
  );

  const executeGetRecentCommands = useCallback(
    async (args: { limit?: number }, agent: Agent): Promise<ToolResult> => {
      const limit = Math.min(Math.max(args.limit || 5, 1), 20);
      const recent = (commandsRef.current[agent.id] || [])
        .slice(-limit)
        .map((cmd) => ({
          id: cmd.id,
          command: cmd.command,
          status: cmd.status,
          outputPreview:
            cmd.output && cmd.output.length > 300
              ? `${cmd.output.substring(0, 300)}...`
              : cmd.output || "",
          createdAt: cmd.createdAt,
        }));

      const stepId = `info-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      appendStep({
        id: stepId,
        kind: "info",
        title: `Fetched last ${recent.length} command(s)`,
        status: "completed",
        detail: recent
          .map((item) => `[${item.status}] ${item.command}`)
          .join("\n"),
        timestamp: Date.now(),
      });

      return {
        status: "ok",
        message: `Returned ${recent.length} commands`,
        data: { commands: recent },
      };
    },
    [appendStep]
  );

  const runToolCall = useCallback(
    async (
      toolName: string,
      args: any,
      agent: Agent,
      allowed: string[] | null,
      runId: string,
      timeoutMs: number,
      modelName?: string
    ): Promise<ToolResult> => {
      if (stopRequestedRef.current) {
        return { status: "error", message: "Run stopped by operator." };
      }

      if (toolName === "run_command") {
        return executeRunCommand(args, agent, allowed, runId, timeoutMs, modelName);
      }

      if (toolName === "get_file") {
        const path = typeof args?.path === "string" ? args.path.trim() : "";
        if (!path) {
          return { status: "error", message: "Path is required for get_file." };
        }
        const command = path.startsWith("get ") ? path : `get ${path}`;
        return executeRunCommand({ command }, agent, allowed, runId, timeoutMs, modelName);
      }

      if (toolName === "get_recent_commands") {
        return executeGetRecentCommands(args, agent);
      }

      // Phase 1: get_executed_commands tool
      if (toolName === "get_executed_commands") {
        return executeGetExecutedCommands(args);
      }

      // Phase 2: complete_task tool
      if (toolName === "complete_task") {
        const {
          status: taskStatus,
          summary,
          findings,
          recommendations,
          risk_assessment,
        } = args as {
          status?: string;
          summary?: string;
          findings?: string[];
          recommendations?: string[];
          risk_assessment?: { high?: string[]; medium?: string[]; low?: string[] };
        };

        // Validate required fields
        if (!taskStatus || !summary) {
          return {
            status: "error",
            message: "complete_task requires 'status' and 'summary' fields",
          };
        }

        // Validate status enum
        const validStatuses = ["completed", "partial", "blocked", "failed"];
        if (!validStatuses.includes(taskStatus)) {
          return {
            status: "error",
            message: `Invalid status '${taskStatus}'. Must be one of: ${validStatuses.join(", ")}`,
          };
        }

        // Build the detail text for display
        const detailParts: string[] = [
          `## Status: ${taskStatus.toUpperCase()}`,
          "",
          `**Summary:** ${summary}`,
        ];

        if (findings && findings.length > 0) {
          detailParts.push("");
          detailParts.push("### Findings");
          findings.forEach((f) => detailParts.push(`- ${f}`));
        }

        if (recommendations && recommendations.length > 0) {
          detailParts.push("");
          detailParts.push("### Recommendations");
          recommendations.forEach((r) => detailParts.push(`- ${r}`));
        }

        if (risk_assessment) {
          const { high, medium, low } = risk_assessment;
          const hasRisks = (high?.length || 0) + (medium?.length || 0) + (low?.length || 0) > 0;

          if (hasRisks) {
            detailParts.push("");
            detailParts.push("### Risk Assessment");

            if (high?.length) {
              detailParts.push("**HIGH:**");
              high.forEach((r) => detailParts.push(`  🔴 ${r}`));
            }
            if (medium?.length) {
              detailParts.push("**MEDIUM:**");
              medium.forEach((r) => detailParts.push(`  🟡 ${r}`));
            }
            if (low?.length) {
              detailParts.push("**LOW:**");
              low.forEach((r) => detailParts.push(`  🟢 ${r}`));
            }
          }
        }

        // Create completion step
        const stepId = `completion-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
        appendStep({
          id: stepId,
          kind: "completion",
          title: `Task ${taskStatus}: ${summary.slice(0, 80)}${summary.length > 80 ? "..." : ""}`,
          detail: detailParts.join("\n"),
          status: "completed",
          timestamp: Date.now(),
        });

        // Return with shouldStop flag
        return {
          status: "ok",
          message: "Task completion recorded",
          data: {
            shouldStop: true,
            taskStatus,
            summary,
            findingsCount: findings?.length || 0,
            recommendationsCount: recommendations?.length || 0,
            commandsExecuted: executedCommandsRef.current.length,
          },
        };
      }

      // Phase 3: get_critical_findings tool
      if (toolName === "get_critical_findings") {
        const filterCategory = (args.category as string) || "all";
        let findings = [...criticalFindingsRef.current];

        if (filterCategory !== "all") {
          findings = findings.filter((f) => f.category === filterCategory);
        }

        const formatted = findings
          .map(
            (f) =>
              `[${f.confidence.toUpperCase()}] ${f.category}: ${f.value} (from: ${f.context})`
          )
          .join("\n");

        const stepId = `info-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
        appendStep({
          id: stepId,
          kind: "info",
          title: `Retrieved ${findings.length} critical finding(s)`,
          detail: formatted || "No findings match the filter.",
          status: "completed",
          timestamp: Date.now(),
        });

        return {
          status: "ok",
          message: `Found ${findings.length} findings`,
          data: { findings },
        };
      }

      // Phase 4: report_progress tool
      if (toolName === "report_progress") {
        const {
          current_phase,
          phase_number,
          os_detected,
          key_findings,
          blockers,
          next_phase,
        } = args as {
          current_phase: string;
          phase_number?: number;
          os_detected?: string;
          key_findings?: string[];
          blockers?: string[];
          next_phase?: string;
        };

        // Store progress
        const progress: PhaseProgress = {
          phaseNumber: phase_number || phaseProgressRef.current.length + 1,
          phaseName: current_phase,
          completedAt: Date.now(),
          osDetected: os_detected as PhaseProgress["osDetected"],
          keyFindings: key_findings || [],
          blockers: blockers || [],
        };

        // Replace if same phase, otherwise append
        const existingIndex = phaseProgressRef.current.findIndex(
          (p) => p.phaseNumber === progress.phaseNumber
        );
        if (existingIndex >= 0) {
          phaseProgressRef.current[existingIndex] = progress;
        } else {
          phaseProgressRef.current.push(progress);
        }

        // Build detail text
        const detailParts = [`Phase ${progress.phaseNumber}: ${current_phase} completed`];
        if (os_detected) {
          detailParts.push(`OS: ${os_detected}`);
        }
        if (key_findings?.length) {
          detailParts.push(`Findings: ${key_findings.join(", ")}`);
        }
        if (blockers?.length) {
          detailParts.push(`Blockers: ${blockers.join(", ")}`);
        }
        if (next_phase) {
          detailParts.push(`Next: ${next_phase}`);
        }

        appendStep({
          id: `progress-${Date.now()}`,
          kind: "info",
          title: `Phase ${progress.phaseNumber} Complete: ${current_phase}`,
          detail: detailParts.join("\n"),
          status: "completed",
          timestamp: Date.now(),
        });

        return {
          status: "ok",
          message: `Progress recorded for phase ${progress.phaseNumber}`,
          data: {
            phasesCompleted: phaseProgressRef.current.length,
            osDetected: os_detected,
          },
        };
      }

      return { status: "error", message: `Unknown tool '${toolName}'` };
    },
    [executeGetRecentCommands, executeRunCommand, executeGetExecutedCommands, appendStep]
  );

  const callModel = useCallback(
    async (
      apiBaseUrl: string,
      apiKey: string | undefined,
      model: string,
      messages: ChatMessage[]
    ) => {
      const baseUrl = normalizeBaseUrl(apiBaseUrl);
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (apiKey && apiKey.trim()) {
        headers.Authorization = `Bearer ${apiKey.trim()}`;
      }

      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          model,
          messages,
          tools: buildToolList(),
          tool_choice: "auto",
        }),
      });

      if (!response.ok) {
        throw new Error(`LLM request failed with status ${response.status}`);
      }

      const data = await response.json();
      return data;
    },
    []
  );

  const callSummaryModel = useCallback(
    async (
      apiBaseUrl: string,
      apiKey: string | undefined,
      model: string,
      messages: ChatMessage[],
      maxTokens: number = 400
    ) => {
      const baseUrl = normalizeBaseUrl(apiBaseUrl);
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (apiKey && apiKey.trim()) {
        headers.Authorization = `Bearer ${apiKey.trim()}`;
      }

      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          model,
          messages,
          max_tokens: maxTokens,
          temperature: 0.3,
        }),
      });

      if (!response.ok) {
        throw new Error(`LLM summary request failed with status ${response.status}`);
      }

      const data = await response.json();
      return data;
    },
    []
  );

  const summarizeHistory = useCallback(
    async (
      apiBaseUrl: string,
      apiKey: string | undefined,
      model: string,
      messages: ChatMessage[]
    ): Promise<boolean> => {
      // Need at least system + goal + some history
      if (messages.length <= 4) {
        return false;
      }

      // Phase 3: Extract critical findings from messages BEFORE we lose them
      const messagesToScan = messages.slice(2); // Skip system + goal
      for (const msg of messagesToScan) {
        if (msg.role === "tool" && typeof msg.content === "string") {
          try {
            const toolResult = JSON.parse(msg.content);
            if (toolResult.data?.output) {
              const findings = extractCriticalFindings(
                toolResult.data.output,
                "pre-summary-extraction"
              );
              // Dedupe against existing
              for (const f of findings) {
                const exists = criticalFindingsRef.current.some(
                  (existing) =>
                    existing.category === f.category &&
                    existing.value.toLowerCase() === f.value.toLowerCase()
                );
                if (!exists) {
                  criticalFindingsRef.current.push(f);
                }
              }
            }
          } catch {
            // Not valid JSON, skip
          }
        }
      }

      // Phase 3: Keep complete thought units instead of arbitrary message count
      const recentMessages = extractRecentThoughtUnits(messages, KEEP_RECENT_UNITS);

      // Calculate what to summarize (everything between goal and recent units)
      const recentStartIndex = messages.length - recentMessages.length;
      const olderMessages = messages.slice(2, recentStartIndex);

      if (olderMessages.length === 0) {
        return false;
      }

      const historyText = olderMessages
        .map((m) => `${m.role}: ${typeof m.content === "string" ? m.content : ""}`)
        .join("\n\n");

      const trimmedHistory =
        historyText.length > SUMMARY_INPUT_LIMIT_CHARS
          ? historyText.slice(historyText.length - SUMMARY_INPUT_LIMIT_CHARS)
          : historyText;

      // Phase 3: Use structured summary prompt
      const summaryPrompt: ChatMessage[] = [
        {
          role: "system",
          content: STRUCTURED_SUMMARY_PROMPT,
        },
        {
          role: "user",
          content: trimmedHistory,
        },
      ];

      try {
        const summaryResponse = await callSummaryModel(
          apiBaseUrl,
          apiKey,
          model,
          summaryPrompt,
          500 // Phase 3: Increased from 400
        );
        const summaryContent =
          summaryResponse?.choices?.[0]?.message?.content?.trim() || "";
        if (!summaryContent) {
          return false;
        }

        const trimmedSummary =
          summaryContent.length > SUMMARY_MAX_CHARS
            ? `${summaryContent.slice(0, SUMMARY_MAX_CHARS)}...`
            : summaryContent;

        const baseMessages = messages.slice(0, 2); // system + goal
        const newMessages = [
          ...baseMessages,
          {
            role: "assistant" as const,
            content: `## Context Summary\n\n${trimmedSummary}`,
          },
          ...recentMessages,
        ];

        messages.length = 0;
        newMessages.forEach((m) => messages.push(m));

        appendStep({
          id: `summary-${Date.now()}`,
          kind: "info",
          title: "Context summarized",
          detail: `Compressed ${olderMessages.length} messages. Preserved ${criticalFindingsRef.current.length} critical findings.`,
          status: "completed",
          timestamp: Date.now(),
        });

        return true;
      } catch (err) {
        appendStep({
          id: `summary-error-${Date.now()}`,
          kind: "info",
          title: "Context summarization failed",
          detail:
            err instanceof Error ? err.message : "Failed to summarize context.",
          status: "error",
          timestamp: Date.now(),
        });
        return false;
      }
    },
    [appendStep, callSummaryModel]
  );

  const startRun = useCallback(
    async (options: AutonomyRunOptions) => {
      if (status === "running") {
        setError("A run is already in progress.");
        return;
      }

      const {
        agent,
        goal,
        model,
        apiBaseUrl,
        apiKey,
        maxSteps = DEFAULT_MAX_STEPS,
        useAllowlist = true,
        timeoutMs = DEFAULT_TIMEOUT_MS,
      } = options;

      const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      stopRequestedRef.current = false;
      runIdRef.current = runId;

      setStatus("running");
      setError(null);
      setSteps([]);

      // Phase 1: Reset command manifest for new run
      executedCommandsRef.current = [];

      // Phase 3: Reset critical findings for new run
      criticalFindingsRef.current = [];

      // Phase 4: Reset phase progress for new run
      phaseProgressRef.current = [];

      const handler = findHandlerForAgent(handlers, agent);
      const allowedCommands =
        useAllowlist && handler?.supportedCommands?.length
          ? handler.supportedCommands.map((cmd) => cmd.toLowerCase())
          : null;

      // Phase 1: Build base system prompt (without command history)
      const baseSystemPrompt = [
        "You are an autonomous operator for a C2 agent.",
        "Plan minimal, precise commands to achieve the goal.",
        "Respect the agent's supported commands and avoid destructive actions unless explicitly required.",
        "",
        `Target agent: ${agent.name} (${agent.id}) • ${agent.os} • ${agent.ip}`,
        handler?.supportedCommands?.length
          ? `Supported commands: ${handler.supportedCommands.join(", ")}`
          : "Supported commands unknown; prefer simple, safe commands.",
        "",
        "## IMPORTANT: Task Completion",
        "When you have completed the objective OR cannot make further progress, you MUST call the `complete_task` tool.",
        "- Use status 'completed' if the goal was achieved",
        "- Use status 'partial' if some progress was made but goal not fully achieved",
        "- Use status 'blocked' if waiting on something external",
        "- Use status 'failed' if the goal cannot be achieved",
        "Do NOT simply stop responding. Always explicitly signal completion.",
      ].join("\n");

      const messages: ChatMessage[] = [
        { role: "system", content: baseSystemPrompt }, // Will be updated each iteration
        { role: "user", content: `Goal: ${goal}` },
      ];

      let toolCallCount = 0;
      let lastSummaryToolCount = 0;

      try {
        for (let stepIndex = 0; stepIndex < maxSteps; stepIndex += 1) {
          if (stopRequestedRef.current) {
            setStatus("stopped");
            runIdRef.current = null;
            return;
          }

          // Phase 1 + Phase 4: Update system prompt with current command history, findings, and phase progress
          messages[0] = {
            role: "system",
            content: buildSystemPromptWithHistory(
              baseSystemPrompt,
              executedCommandsRef.current,
              criticalFindingsRef.current,
              phaseProgressRef.current
            ),
          };

          const data = await callModel(apiBaseUrl, apiKey, model.id, messages);

          if (stopRequestedRef.current) {
            setStatus("stopped");
            runIdRef.current = null;
            return;
          }

          const choice = data?.choices?.[0];
          const assistantMessage: ChatMessage | undefined = choice?.message;
          const finishReason: string | undefined = choice?.finish_reason;

          if (!assistantMessage) {
            throw new Error("LLM returned no message.");
          }

          const toolCalls = assistantMessage.tool_calls || [];

          // Record the model's thought/plan as a lightweight timeline entry (without overwhelming the UI)
          const rawThought =
            typeof assistantMessage.content === "string"
              ? assistantMessage.content.trim()
              : "";

          const fallbackThought =
            !rawThought && toolCalls.length > 0
              ? `Planning tool calls: ${toolCalls
                  .map((tc) => tc.function?.name || "tool")
                  .join(", ")}`
              : "";

          const thoughtText = rawThought || fallbackThought;

          if (thoughtText) {
            const trimmedThought = thoughtText.length > 1200
              ? `${thoughtText.slice(0, 1200)}...`
              : thoughtText;

            appendStep({
              id: `thought-${Date.now()}`,
              kind: "thought",
              title: "Model thoughts",
              detail: trimmedThought,
              status: "completed",
              timestamp: Date.now(),
            });
          }

          messages.push(assistantMessage);

          if (toolCalls.length === 0) {
            appendStep({
              id: `info-${Date.now()}`,
              kind: "info",
              title: "Model returned no tool calls",
              detail:
                "The model stopped without calling complete_task. This may indicate it finished thinking or encountered an issue. Review the last thought for context.",
              status: "completed",
              timestamp: Date.now(),
            });
            setStatus("completed");
            runIdRef.current = null;
            return;
          }

          for (const toolCall of toolCalls) {
            const parsedArgs =
              toolCall.function?.arguments && toolCall.function.arguments.trim().length
                ? (() => {
                    try {
                      return JSON.parse(toolCall.function.arguments);
                    } catch {
                      return {};
                    }
                  })()
                : {};

            const toolResult = await runToolCall(
              toolCall.function.name,
              parsedArgs,
              agent,
              allowedCommands,
              runId,
              timeoutMs,
              model.name || model.id
            );

            messages.push({
              role: "tool",
              tool_call_id: toolCall.id,
              content: JSON.stringify(toolResult),
            });

            // Phase 2: Check for completion signal
            if (toolResult.data?.shouldStop) {
              setStatus("completed");
              runIdRef.current = null;
              return;
            }

            if (stopRequestedRef.current) {
              setStatus("stopped");
              runIdRef.current = null;
              return;
            }
          }

          toolCallCount += toolCalls.length;

          // Context budgeting: summarize when near budget or after enough actions
          const estimatedTokens = estimateTokensFromMessages(messages);
          const shouldSummarizeBySize = estimatedTokens > CONTEXT_TOKEN_THRESHOLD;
          const shouldSummarizeByActions =
            toolCallCount - lastSummaryToolCount >= SUMMARIZE_MIN_ACTIONS &&
            estimatedTokens > CONTEXT_TOKEN_THRESHOLD * 0.7;

          if ((shouldSummarizeBySize || shouldSummarizeByActions) && messages.length > KEEP_RECENT_MESSAGES + 2) {
            const summarized = await summarizeHistory(
              apiBaseUrl,
              apiKey,
              model.id,
              messages
            );
            if (summarized) {
              lastSummaryToolCount = toolCallCount;
            }
          }

          if (finishReason === "stop") {
            setStatus("completed");
            runIdRef.current = null;
            return;
          }
        }

        // Phase 2: Max steps reached without explicit completion
        appendStep({
          id: `info-${Date.now()}`,
          kind: "info",
          title: "Maximum steps reached without explicit completion",
          detail:
            "The agent reached the step limit without calling complete_task. Review the commands executed and consider increasing max steps or refining the goal.",
          status: "completed",
          timestamp: Date.now(),
        });

        setStatus("completed");
        runIdRef.current = null;
      } catch (err) {
        if (runIdRef.current === runId) {
          setError(err instanceof Error ? err.message : "Run failed.");
          setStatus("error");
          runIdRef.current = null;
        }
      }
    },
    [appendStep, callModel, handlers, runToolCall, status, summarizeHistory]
  );

  const stopRun = useCallback(() => {
    stopRequestedRef.current = true;
    if (status === "running") {
      setStatus("stopped");
    }
  }, [status]);

  return {
    status,
    steps,
    error,
    startRun,
    stopRun,
    isRunning: status === "running",
  };
}
