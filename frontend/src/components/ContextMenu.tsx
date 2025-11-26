import React, { useState, useEffect, useRef } from 'react';
import { FaUpload, FaSyringe, FaTimes, FaChevronRight, FaCog, FaTerminal } from 'react-icons/fa';
import { getScripts } from './Scripts';

interface Script {
  id: string;
  name: string;
  commands: string[];
  createdAt: string;
}

import { Agent, AgentHandler } from '../hooks/useWebSocket';

interface ContextMenuProps {
  isVisible: boolean;
  x: number;
  y: number;
  agent: Agent | null;
  handlers?: AgentHandler[];
  onClose: () => void;
  onPut: () => void;
  onInject: () => void;
  onScriptExecute: (script: Script) => void;
}

export default function ContextMenu({ isVisible, x, y, agent, handlers, onClose, onPut, onInject, onScriptExecute }: ContextMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);
  const [adjustedPosition, setAdjustedPosition] = useState({ x, y });
  const [scriptsExpanded, setScriptsExpanded] = useState(false);
  const [scripts, setScripts] = useState<Script[]>([]);

  // Check if agent supports injection
  const canInject = React.useMemo(() => {
    if (!agent || !handlers) return false;

    // Find handler for this agent
    // The agent.handlerName matches the handler.agentName
    // Or we can match by ID if available, but let's try name first as it's visible in table
    const handler = handlers.find(h => h.agentName === agent.handlerName);

    if (!handler) return false;

    return handler.supportedCommands.includes('injectsc');
  }, [agent, handlers]);

  // Calculate smart positioning to keep menu within viewport
  useEffect(() => {
    if (!isVisible) return;

    // Pre-calculate position without needing the DOM element
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const menuWidth = 200; // Approximate menu width
    const menuHeight = 100; // Approximate menu height

    let adjustedX = x;
    let adjustedY = y;

    // Check if menu would go off the right edge
    if (x + menuWidth > viewportWidth) {
      adjustedX = viewportWidth - menuWidth - 10; // 10px margin
    }

    // Check if menu would go off the bottom edge
    if (y + menuHeight > viewportHeight) {
      adjustedY = viewportHeight - menuHeight - 10; // 10px margin
    }

    // Check for bottom terminal overlap (assuming terminal is at bottom)
    const bottomTerminal = document.querySelector('.bottom-terminal');
    if (bottomTerminal) {
      const terminalRect = bottomTerminal.getBoundingClientRect();
      const terminalTop = terminalRect.top;

      // If menu would overlap with terminal, position it above the terminal
      if (adjustedY + menuHeight > terminalTop) {
        adjustedY = terminalTop - menuHeight - 10;
      }
    }

    // Ensure menu doesn't go off the left or top edges
    adjustedX = Math.max(10, adjustedX);
    adjustedY = Math.max(10, adjustedY);

    setAdjustedPosition({ x: adjustedX, y: adjustedY });
  }, [isVisible, x, y]);

  // Load scripts when menu opens
  useEffect(() => {
    if (isVisible) {
      setScripts(getScripts());
      setScriptsExpanded(false);
    }
  }, [isVisible]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    if (isVisible) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleEscape);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isVisible, onClose]);

  if (!isVisible) return null;

  const handleScriptClick = (script: Script) => {
    onScriptExecute(script);
    onClose();
  };

  return (
    <div
      ref={menuRef}
      className={`context-menu ${isVisible ? 'visible' : ''}`}
      style={{
        position: 'fixed',
        left: adjustedPosition.x,
        top: adjustedPosition.y,
        zIndex: 1000
      }}
    >
      <div className="context-menu-item" onClick={onPut}>
        <FaUpload className="context-menu-icon" />
        <span>Put File</span>
      </div>
      {canInject && (
        <div className="context-menu-item" onClick={onInject}>
          <FaSyringe className="context-menu-icon" />
          <span>Inject</span>
        </div>
      )}

      {/* Scripts Section */}
      <div className="context-menu-divider" />
      <div className="context-menu-item-wrapper">
        <div
          className="context-menu-item context-menu-expandable"
          onClick={(e) => {
            e.stopPropagation();
            setScriptsExpanded(!scriptsExpanded);
          }}
        >
          <FaCog className="context-menu-icon" />
          <span>Scripts</span>
          <FaChevronRight
            className={`context-menu-chevron ${scriptsExpanded ? 'expanded' : ''}`}
          />
        </div>

        {scriptsExpanded && (
          <div className="context-menu-submenu">
            {scripts.length === 0 ? (
              <div className="context-menu-item disabled">
                <span style={{ fontSize: '0.85rem', fontStyle: 'italic' }}>No scripts available</span>
              </div>
            ) : (
              scripts.map((script) => (
                <div
                  key={script.id}
                  className="context-menu-item context-menu-script"
                  onClick={() => handleScriptClick(script)}
                  title={`${script.commands.length} command${script.commands.length !== 1 ? 's' : ''}`}
                >
                  <FaTerminal className="context-menu-icon" style={{ fontSize: '0.9rem' }} />
                  <span>{script.name}</span>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
