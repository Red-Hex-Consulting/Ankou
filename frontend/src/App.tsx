import { useState } from "react";
import Sidebar from "./components/Sidebar";
import AgentsTable from "./components/AgentsTable";
import GlobalTerminal from "./components/GlobalTerminal";
import BottomTerminal from "./components/BottomTerminal";
import AI from "./components/AI";
import PolyEngine from "./components/PolyEngine";
import Scripts from "./components/Scripts";
import Loot from "./components/Loot";
import Listeners from "./components/Listeners";
import Handlers from "./components/Handlers";
import Operators from "./components/Operators";
import Logs from "./components/Logs";
import LoginScreen from "./components/LoginScreen";
import LoadingSpinner from "./components/LoadingSpinner";
import { useTerminal } from "./hooks/useTerminal";
import { useGlobalTerminal } from "./hooks/useGlobalTerminal";
import { useWebSocket } from "./hooks/useWebSocket";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { ServerProvider } from "./contexts/ServerContext";
import "./App.css";

function AppContent() {
  const { isAuthenticated, loading, login, logout } = useAuth();
  const [activeTab, setActiveTab] = useState("agents");
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  
  // Use custom hooks for terminal functionality - ALWAYS call hooks at the top level
  const terminal = useTerminal();
  const { agents, isConnected, ws } = useWebSocket(activeTab === "agents");
  const globalTerminal = useGlobalTerminal({ ws, isConnected });
  
  // Show login screen if not authenticated
  if (loading) {
    return (
      <div style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'var(--bg-primary)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--text-primary)',
        gap: '1rem'
      }}>
        <LoadingSpinner size={48} />
        <div style={{
          fontSize: '1.1rem',
          color: 'var(--text-secondary)'
        }}>
          Loading Ankou...
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginScreen onLogin={login} />;
  }

  const renderMainContent = () => {
    switch (activeTab) {
      case "agents":
        return (
          <AgentsTable 
            onAgentClick={terminal.handleAgentClick}
            onAgentPut={(agent) => {
              // Open file upload for specific agent
              setSelectedAgentForUpload(agent);
            }}
            onAgentInject={(agent) => {
              // Open injection dialog for specific agent
              setSelectedAgentForInject(agent);
            }}
            isActive={activeTab === "agents"}
          />
        );
      case "terminal":
        return (
          <GlobalTerminal
            terminalHistory={globalTerminal.globalTerminalHistory}
            currentCommand={globalTerminal.globalCurrentCommand}
            setCurrentCommand={globalTerminal.setGlobalCurrentCommand}
            onCommandSubmit={globalTerminal.handleGlobalCommandSubmit}
            onFileUpload={(file, remotePath) => {
              // Handle file upload for global terminal
            }}
            agents={agents}
          />
        );
      case "ai":
        return <AI isActive={activeTab === "ai"} />;
      case "poly-engine":
        return <PolyEngine isActive={activeTab === "poly-engine"} />;
      case "loot":
        return <Loot isActive={activeTab === "loot"} />;
      case "listeners":
        return <Listeners />;
      case "handlers":
        return <Handlers />;
      case "operators":
        return <Operators />;
      case "logs":
        return <Logs />;
      case "scripts":
        return <Scripts isActive={activeTab === "scripts"} />;
      default:
        return (
          <>
            <div className="content-header">
              <h1>C2 Dashboard</h1>
              <div className="status-indicators">
                <div className="status-item">
                  <span className="status-dot online"></span>
                  <span>System Online</span>
                </div>
                <div className="status-item">
                  <span className="status-dot active"></span>
                  <span>Active Agents: Loading...</span>
                </div>
              </div>
            </div>

            <div className="dashboard-grid">
              <div className="dashboard-card">
                <h3>System Status</h3>
                <p>All systems operational</p>
              </div>
              <div className="dashboard-card">
                <h3>Active Sessions</h3>
                <p>Loading agents...</p>
              </div>
              <div className="dashboard-card">
                <h3>Security Status</h3>
                <p>No threats detected</p>
              </div>
              <div className="dashboard-card">
                <h3>Data Transfer</h3>
                <p>2.4 GB processed today</p>
              </div>
            </div>
          </>
        );
    }
  };

  return (
    <div className="app">
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        isConnected={isConnected}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
        onLogout={logout}
      />
      
      <div className={`main-content ${terminal.isTerminalOpen ? 'terminal-open' : ''} ${isSidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        {renderMainContent()}
      </div>

      <BottomTerminal
        isTerminalOpen={terminal.isTerminalOpen}
        terminalTabs={terminal.terminalTabs}
        activeTerminalTab={terminal.activeTerminalTab}
        terminalHeight={terminal.terminalHeight}
        isDragging={terminal.isDragging}
        currentCommand={terminal.currentCommand}
        setCurrentCommand={terminal.setCurrentCommand}
        onCommandSubmit={terminal.handleCommandSubmit}
        onFileUpload={(file, remotePath) => {
          // Handle file upload for bottom terminal
        }}
        onCloseTab={terminal.closeTerminalTab}
        onSetActiveTab={terminal.setActiveTerminalTab}
        onMouseDown={terminal.handleMouseDown}
        dragRef={terminal.dragRef}
        onLoadMoreHistory={terminal.loadMoreHistory}
        loadingMoreHistory={terminal.loadingMoreHistory}
        commandTotalCounts={terminal.commandTotalCounts}
      />
    </div>
  );
}

function App() {
  return (
    <ServerProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ServerProvider>
  );
}

export default App;
