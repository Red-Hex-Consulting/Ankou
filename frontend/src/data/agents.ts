export interface Agent {
  id: number;
  name: string;
  status: string;
  ip: string;
  lastSeen: string;
  os: string;
}

export const agents: Agent[] = [
  { id: 1, name: "Agent-001", status: "Online", ip: "192.168.1.100", lastSeen: "2 minutes ago", os: "Windows 10" },
  { id: 2, name: "Agent-002", status: "Online", ip: "192.168.1.101", lastSeen: "5 minutes ago", os: "Ubuntu 20.04" },
  { id: 3, name: "Agent-003", status: "Offline", ip: "192.168.1.102", lastSeen: "1 hour ago", os: "Windows 11" },
  { id: 4, name: "Agent-004", status: "Online", ip: "192.168.1.103", lastSeen: "1 minute ago", os: "macOS 13" },
  { id: 5, name: "Agent-005", status: "Online", ip: "192.168.1.104", lastSeen: "3 minutes ago", os: "CentOS 8" },
  { id: 6, name: "Agent-006", status: "Online", ip: "192.168.1.105", lastSeen: "4 minutes ago", os: "Windows 10" },
  { id: 7, name: "Agent-007", status: "Online", ip: "192.168.1.106", lastSeen: "6 minutes ago", os: "Ubuntu 22.04" },
  { id: 8, name: "Agent-008", status: "Offline", ip: "192.168.1.107", lastSeen: "2 hours ago", os: "Windows 11" },
  { id: 9, name: "Agent-009", status: "Online", ip: "192.168.1.108", lastSeen: "30 seconds ago", os: "macOS 14" },
  { id: 10, name: "Agent-010", status: "Online", ip: "192.168.1.109", lastSeen: "1 minute ago", os: "Debian 12" },
  { id: 11, name: "Agent-011", status: "Online", ip: "192.168.1.110", lastSeen: "7 minutes ago", os: "Windows 10" },
  { id: 12, name: "Agent-012", status: "Online", ip: "192.168.1.111", lastSeen: "2 minutes ago", os: "Ubuntu 20.04" },
  { id: 13, name: "Agent-013", status: "Offline", ip: "192.168.1.112", lastSeen: "3 hours ago", os: "Windows 11" },
  { id: 14, name: "Agent-014", status: "Online", ip: "192.168.1.113", lastSeen: "45 seconds ago", os: "macOS 13" },
  { id: 15, name: "Agent-015", status: "Online", ip: "192.168.1.114", lastSeen: "5 minutes ago", os: "CentOS 9" },
];
