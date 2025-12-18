import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { useWebSocket, Agent, Command, AgentHandler } from "./useWebSocket";

type RunStatus = "idle" | "running" | "completed" | "stopped" | "error";

type StepStatus = "pending" | "running" | "completed" | "blocked" | "error";
type StepKind = "command" | "info" | "thought";

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

const DEFAULT_MAX_STEPS = 8;
const DEFAULT_TIMEOUT_MS = 120000;

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

export function useAutonomyRunner() {
  const { user } = useAuth();
  const { sendCommand, commands, handlers } = useWebSocket(true);

  const [status, setStatus] = useState<RunStatus>("idle");
  const [steps, setSteps] = useState<AutonomyStep[]>([]);
  const [error, setError] = useState<string | null>(null);

  const commandsRef = useRef<{ [agentId: string]: Command[] }>({});
  const stopRequestedRef = useRef(false);
  const runIdRef = useRef<string | null>(null);

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

        updateStep(stepId, (step) => ({
          ...step,
          commandId: result.id,
          output: (result.output || "").trim(),
          status: result.status === "completed" ? "completed" : "error",
        }));

        return {
          status: result.status === "completed" ? "ok" : "error",
          message: `Command ${result.status}`,
          data: {
            commandId: result.id,
            status: result.status,
            output: result.output,
          },
        };
      } catch (err) {
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
    [appendStep, sendCommand, updateStep, user?.username, waitForCommandResult]
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

      return { status: "error", message: `Unknown tool '${toolName}'` };
    },
    [executeGetRecentCommands, executeRunCommand]
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

      const handler = findHandlerForAgent(handlers, agent);
      const allowedCommands =
        useAllowlist && handler?.supportedCommands?.length
          ? handler.supportedCommands.map((cmd) => cmd.toLowerCase())
          : null;

      const systemPrompt = [
        "You are an autonomous operator for a C2 agent.",
        "Plan minimal, precise commands to achieve the goal.",
        "Respect the agent's supported commands and avoid destructive actions unless explicitly required.",
        `Target agent: ${agent.name} (${agent.id}) • ${agent.os} • ${agent.ip}`,
        handler?.supportedCommands?.length
          ? `Supported commands: ${handler.supportedCommands.join(", ")}`
          : "Supported commands unknown; prefer simple, safe commands.",
      ].join("\n");

      const messages: ChatMessage[] = [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Goal: ${goal}` },
      ];

      try {
        for (let stepIndex = 0; stepIndex < maxSteps; stepIndex += 1) {
          if (stopRequestedRef.current) {
            setStatus("stopped");
            runIdRef.current = null;
            return;
          }

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
              title: "Model returned no tool calls; stopping.",
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

            if (stopRequestedRef.current) {
              setStatus("stopped");
              runIdRef.current = null;
              return;
            }
          }

          if (finishReason === "stop") {
            setStatus("completed");
            runIdRef.current = null;
            return;
          }
        }

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
    [appendStep, callModel, handlers, runToolCall, status]
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
