import { useEffect, useMemo, useState, useRef } from "react";
import { FaPlay, FaStop, FaRobot, FaExclamationTriangle, FaLightbulb, FaCog } from "react-icons/fa";
import { useWebSocket } from "../hooks/useWebSocket";
import { useAutonomyRunner } from "../hooks/useAutonomyRunner";
import {
  API_BASE_URL_STORAGE_KEY,
  API_KEY_STORAGE_KEY,
  DEFAULT_API_BASE_URL,
  MODELS_STORAGE_KEY,
  SELECTED_MODEL_STORAGE_KEY,
} from "../utils/aiSettings";
import { RED_TEAM_TRIAGE_PROMPT } from "../utils/prompts";
import "./AutonomousAgent.css";

interface Model {
  id: string;
  name: string;
  provider?: string;
}

interface AutonomousAgentProps {
  isActive: boolean;
}

export default function AutonomousAgent({ isActive }: AutonomousAgentProps) {
  const { agents } = useWebSocket(true);
  const { status, steps, error, startRun, stopRun, isRunning } = useAutonomyRunner();

  const [apiBaseUrl, setApiBaseUrl] = useState(DEFAULT_API_BASE_URL);
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState<Model[]>([]);
  const [selectedModel, setSelectedModel] = useState<Model | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [showConfig, setShowConfig] = useState(false);

  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [goal, setGoal] = useState("");
  const [maxSteps, setMaxSteps] = useState(15);
  const [useAllowlist, setUseAllowlist] = useState(true);
  const [timeoutSeconds, setTimeoutSeconds] = useState(120);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  // Load cached settings on mount
  useEffect(() => {
    const cachedBase = localStorage.getItem(API_BASE_URL_STORAGE_KEY);
    const cachedKey = localStorage.getItem(API_KEY_STORAGE_KEY);
    const cachedModels = localStorage.getItem(MODELS_STORAGE_KEY);
    const cachedModel = localStorage.getItem(SELECTED_MODEL_STORAGE_KEY);

    if (cachedBase) setApiBaseUrl(cachedBase);
    if (cachedKey) setApiKey(cachedKey);
      if (cachedModels) {
        try {
          const parsed = JSON.parse(cachedModels);
          const parsedModels: Model[] = Array.isArray(parsed) ? parsed : [];
          setModels(parsedModels);
          if (cachedModel) {
            const parsedSelected: Model | null = JSON.parse(cachedModel);
            const match = parsedSelected
              ? parsedModels.find((m) => m.id === parsedSelected.id)
              : null;
            if (match) setSelectedModel(match);
          }
          // Auto-connect if we have cached models
          if (parsedModels.length > 0) {
            setIsConnected(true);
          }
        } catch {
          setModels([]);
        }
      }
  }, []);

  const handleLoadModels = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsConnecting(true);
    setConnectError(null);

    try {
      const baseUrl = apiBaseUrl.trim().replace(/\/+$/, "");
      const headers: Record<string, string> = {
        Accept: "application/json",
        "Content-Type": "application/json",
      };
      if (apiKey.trim()) {
        headers.Authorization = `Bearer ${apiKey.trim()}`;
      }

      const response = await fetch(`${baseUrl}/models`, { headers });
      if (!response.ok) {
        throw new Error(`Failed to fetch models (${response.status})`);
      }

      const text = await response.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error(`Invalid response from models endpoint: ${text.slice(0, 120)}`);
      }

      let modelList: Model[] = [];
      if (Array.isArray(parsed)) {
        modelList = parsed.map((m: any) => ({ id: m.id || m.name, name: m.name || m.id, provider: m.provider || m.source }));
      } else if (Array.isArray(parsed?.data)) {
        modelList = parsed.data.map((m: any) => ({ id: m.id || m.name, name: m.name || m.id, provider: m.provider || m.source }));
      } else if (Array.isArray(parsed?.models)) {
        modelList = parsed.models.map((m: any) => ({ id: m.id || m.name, name: m.name || m.id, provider: m.provider || m.source }));
      }

      if (modelList.length === 0) {
        throw new Error("No models returned from API");
      }

      setModels(modelList);
      setSelectedModel(modelList[0]);
      setIsConnected(true);
      setShowConfig(false);
      localStorage.setItem(API_BASE_URL_STORAGE_KEY, baseUrl);
      if (apiKey.trim()) {
        localStorage.setItem(API_KEY_STORAGE_KEY, apiKey.trim());
      } else {
        localStorage.removeItem(API_KEY_STORAGE_KEY);
      }
      localStorage.setItem(MODELS_STORAGE_KEY, JSON.stringify(modelList));
      localStorage.setItem(SELECTED_MODEL_STORAGE_KEY, JSON.stringify(modelList[0]));
    } catch (err) {
      setConnectError(err instanceof Error ? err.message : "Failed to load models.");
    } finally {
      setIsConnecting(false);
    }
  };

  const agentList = Array.isArray(agents) ? agents : [];

  const selectedAgent = useMemo(() => {
    const pool = Array.isArray(agentList) ? agentList : [];
    return pool.find((a) => a.id === selectedAgentId) || null;
  }, [agentList, selectedAgentId]);

  const canStart = Boolean(
    selectedAgent && selectedModel && goal.trim().length > 0 && !isRunning
  );

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [steps]);

  const handleStart = () => {
    if (!selectedAgent || !selectedModel) return;
    startRun({
      agent: selectedAgent,
      goal: goal.trim(),
      model: selectedModel,
      apiBaseUrl,
      apiKey,
      maxSteps,
      useAllowlist,
      timeoutMs: Math.max(timeoutSeconds * 1000, 5000),
    });
  };

  if (!isActive) {
    return null;
  }

  return (
    <div className="autonomy-container">
      <div className="autonomy-header glassy">
        <div className="autonomy-title">
          <FaRobot /> <span>Autonomous Agent</span>
        </div>
        <div className="autonomy-header-right">
          <div className={`status-chip ${status}`}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </div>
          {isConnected && (
            <button 
              className="config-toggle-btn" 
              onClick={() => setShowConfig(!showConfig)}
              title="Configure AI Settings"
            >
              <FaCog />
            </button>
          )}
        </div>
      </div>

      <div className="autonomy-grid">
        <div className="autonomy-panel glassy">
          {!isConnected || showConfig ? (
            <form className="autonomy-form" onSubmit={handleLoadModels}>
              <div className="form-group">
                <label>API Base URL</label>
                <input
                  type="url"
                  value={apiBaseUrl}
                  onChange={(e) => setApiBaseUrl(e.target.value)}
                  placeholder="http://localhost:11434/v1"
                  required
                />
              </div>
              <div className="form-group">
                <label>API Key (optional)</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Only needed for hosted providers"
                />
              </div>
              <div className="form-group">
                <label>Model</label>
                <div className="model-row">
                  <select
                    value={selectedModel?.id || ""}
                    onChange={(e) => {
                      const model = (models || []).find((m) => m.id === e.target.value) || null;
                      setSelectedModel(model);
                      if (model) {
                        localStorage.setItem(SELECTED_MODEL_STORAGE_KEY, JSON.stringify(model));
                      }
                    }}
                  >
                    <option value="">Choose a model...</option>
                    {models.map((model) => (
                      <option key={model.id} value={model.id}>
                        {model.name} {model.provider ? `(${model.provider})` : ""}
                      </option>
                    ))}
                  </select>
                  <button type="submit" className="secondary-btn" disabled={isConnecting}>
                    {isConnecting ? "Loading..." : "Load Models"}
                  </button>
                </div>
                {connectError && <div className="inline-error">{connectError}</div>}
              </div>
              {showConfig && (
                <button 
                  type="button" 
                  className="secondary-btn" 
                  onClick={() => setShowConfig(false)}
                >
                  Close Config
                </button>
              )}
            </form>
          ) : (
            <div className="connected-info">
              <div className="connection-status">
                <div className="status-indicator connected"></div>
                <div>
                  <div className="connection-title">AI Connected</div>
                  <div className="connection-subtitle">
                    {apiBaseUrl} • {selectedModel?.name || "No model selected"}
                  </div>
                </div>
              </div>
              <div className="form-group">
                <label>Model</label>
                <select
                  value={selectedModel?.id || ""}
                  onChange={(e) => {
                    const model = (models || []).find((m) => m.id === e.target.value) || null;
                    setSelectedModel(model);
                    if (model) {
                      localStorage.setItem(SELECTED_MODEL_STORAGE_KEY, JSON.stringify(model));
                    }
                  }}
                >
                  <option value="">Choose a model...</option>
                  {models.map((model) => (
                    <option key={model.id} value={model.id}>
                      {model.name} {model.provider ? `(${model.provider})` : ""}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}

          <div className="form-group">
            <label>Target Agent</label>
            <select
              value={selectedAgentId}
              onChange={(e) => setSelectedAgentId(e.target.value)}
            >
              <option value="">Select an agent...</option>
              {agentList.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name} ({agent.ip}) • {agent.os}
                </option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label>Goal</label>
            <textarea
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              placeholder="Describe what the agent should accomplish..."
              rows={4}
            />
          </div>

          <div className="template-card">
            <div className="template-info">
              <FaLightbulb className="template-icon" />
              <div>
                <div className="template-title">Red Team Triage Playbook</div>
                <div className="template-subtitle">Load a pre-built reconnaissance and system assessment prompt.</div>
              </div>
            </div>
            <button
              type="button"
              className="secondary-btn"
              onClick={() => setGoal(RED_TEAM_TRIAGE_PROMPT)}
            >
              Use This Prompt
            </button>
          </div>

          <div className="settings-row">
            <div className="settings-group">
              <label>Max Steps</label>
              <input
                type="number"
                min={1}
                max={50}
                value={maxSteps}
                onChange={(e) => setMaxSteps(Math.min(50, Math.max(1, Number(e.target.value))))}
              />
              <span className="settings-hint">Forced completion at limit (15-25 recommended)</span>
            </div>
            <div className="settings-group">
              <label>Timeout (seconds)</label>
              <input
                type="number"
                min={5}
                max={600}
                value={timeoutSeconds}
                onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
              />
              <span className="settings-hint">Per-command timeout</span>
            </div>
            <div className="settings-group checkbox">
              <label>
                <input
                  type="checkbox"
                  checked={useAllowlist}
                  onChange={(e) => setUseAllowlist(e.target.checked)}
                />
                Enforce handler allowlist
              </label>
            </div>
          </div>

          <div className="action-row">
            <button
              className="primary-btn"
              onClick={handleStart}
              disabled={!canStart}
            >
              <FaPlay /> Start
            </button>
            <button
              className="stop-btn"
              onClick={stopRun}
              disabled={!isRunning}
              type="button"
            >
              <FaStop /> Stop
            </button>
          </div>

          {error && (
            <div className="inline-error">
              <FaExclamationTriangle /> {error}
            </div>
          )}
        </div>

        <div className="autonomy-log">
          <div className="log-header">Command Timeline</div>
          {steps.length === 0 ? (
            <div className="log-empty">No steps yet. Start a run to see activity.</div>
          ) : (
            <div className="log-entries">
              {steps.map((step, idx) => (
                <div key={step.id} className={`log-entry ${step.status}`}>
                  <div className="log-entry-header">
                    <span className="log-title">{step.title}</span>
                    <span className={`badge ${step.status}`}>{step.status}</span>
                  </div>

                  {step.commandText && (
                    <div className="log-command">
                      <span className="log-label">Command</span>
                      <div className="log-command-line">
                        <span className="prompt">$</span>
                        <code>{step.commandText}</code>
                      </div>
                    </div>
                  )}

                  {step.detail && (
                    <div className="log-output-box subtle">
                      <span className="log-label">{step.kind === "thought" ? "Model Thoughts" : "Info"}</span>
                      <pre className="log-output">{step.detail}</pre>
                    </div>
                  )}

                  {step.output && (
                    <div className="log-output-box">
                      <span className="log-label">Output</span>
                      <pre className="log-output scrollable">{step.output}</pre>
                    </div>
                  )}
                  {idx === steps.length - 1 && <div ref={logEndRef} className="log-scroll-anchor" />}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
