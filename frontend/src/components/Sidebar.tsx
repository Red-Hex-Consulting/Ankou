import { FaHeart, FaChevronLeft, FaChevronRight, FaSignOutAlt, FaProjectDiagram } from "react-icons/fa";
import { GiScythe, GiOctopus, GiMagicGate } from "react-icons/gi";
import { RiSkull2Fill } from "react-icons/ri";
import { SiOllama } from "react-icons/si";
import { FaDatabase, FaFileAlt, FaUserSecret, FaFileCode, FaCog } from "react-icons/fa";
import { LuRadioTower } from "react-icons/lu";
import packageJson from "../../package.json";

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isConnected?: boolean;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  onLogout: () => void;
}

const sidebarItems = [
  { id: "agents", label: "Agents", icon: RiSkull2Fill },
  { id: "terminal", label: "Global Commands", icon: GiOctopus },
  { id: "loot", label: "Loot", icon: FaDatabase },
  { id: "ai", label: "AI Chat", icon: SiOllama },
  { id: "poly-engine", label: "Poly Engine", icon: GiMagicGate },
  { id: "listeners", label: "Listeners", icon: LuRadioTower },
  { id: "handlers", label: "Handlers", icon: FaProjectDiagram },
  { id: "logs", label: "Logs", icon: FaFileAlt },
  { id: "operators", label: "Operators", icon: FaUserSecret },
  { id: "scripts", label: "Automation", icon: FaCog },
];

export default function Sidebar({ activeTab, setActiveTab, isConnected, isCollapsed, onToggleCollapse, onLogout }: SidebarProps) {
  return (
    <div className={`sidebar ${isCollapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="logo-section">
          <GiScythe className="scythe-icon" />
          {!isCollapsed && <span className="ankou-text">Ankou</span>}
        </div>
        {!isCollapsed && <div className="version-text">v{packageJson.version}</div>}
        <button className="collapse-btn" onClick={onToggleCollapse}>
          {isCollapsed ? <FaChevronRight /> : <FaChevronLeft />}
        </button>
      </div>
      
      <nav className="sidebar-nav">
        {sidebarItems.slice(0, 3).map((item) => {
          const IconComponent = item.icon;
          return (
            <button
              key={item.id}
              className={`sidebar-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              title={isCollapsed ? item.label : undefined}
            >
              <IconComponent className="sidebar-icon" />
              {!isCollapsed && <span className="sidebar-label">{item.label}</span>}
            </button>
          );
        })}
        
        <div className="sidebar-separator"></div>

        {sidebarItems.slice(3, 5).map((item) => {
          const IconComponent = item.icon;
          return (
            <button
              key={item.id}
              className={`sidebar-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              title={isCollapsed ? item.label : undefined}
            >
              <IconComponent className="sidebar-icon" />
              {!isCollapsed && <span className="sidebar-label">{item.label}</span>}
            </button>
          );
        })}
        
        <div className="sidebar-separator"></div>

        {sidebarItems.slice(5, 8).map((item) => {
          const IconComponent = item.icon;
          return (
            <button
              key={item.id}
              className={`sidebar-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              title={isCollapsed ? item.label : undefined}
            >
              <IconComponent className="sidebar-icon" />
              {!isCollapsed && <span className="sidebar-label">{item.label}</span>}
            </button>
          );
        })}
        
        <div className="sidebar-separator"></div>

        {sidebarItems.slice(8).map((item) => {
          const IconComponent = item.icon;
          return (
            <button
              key={item.id}
              className={`sidebar-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              title={isCollapsed ? item.label : undefined}
            >
              <IconComponent className="sidebar-icon" />
              {!isCollapsed && <span className="sidebar-label">{item.label}</span>}
            </button>
          );
        })}
        
        {/* Logout Button */}
        <button
          className="sidebar-item logout-btn"
          onClick={onLogout}
          title={isCollapsed ? "Logout" : undefined}
        >
          <FaSignOutAlt className="sidebar-icon" />
          {!isCollapsed && <span className="sidebar-label">Logout</span>}
        </button>
      </nav>
      
      {!isCollapsed && (
        <div className="connection-status-mini">
          <div className="connection-label">
            <span className={`status-indicator-mini ${isConnected ? 'connected' : 'disconnected'}`}></span>
            <span className="connection-text">C2 connection</span>
          </div>
        </div>
      )}
      
      {!isCollapsed && (
        <div className="sidebar-footer">
          <span>by redhex</span>
          <FaHeart className="heart-icon" />
        </div>
      )}
    </div>
  );
}
