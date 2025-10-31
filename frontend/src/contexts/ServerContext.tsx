import React, { createContext, useContext, useState, ReactNode } from 'react';

interface ServerContextType {
  serverUrl: string;
  setServerUrl: (url: string) => void;
}

const ServerContext = createContext<ServerContextType | undefined>(undefined);

export const useServerUrl = () => {
  const context = useContext(ServerContext);
  if (context === undefined) {
    throw new Error('useServerUrl must be used within a ServerProvider');
  }
  return context;
};

interface ServerProviderProps {
  children: ReactNode;
}

export const ServerProvider: React.FC<ServerProviderProps> = ({ children }) => {
  // Dynamically determine the server URL based on current hostname
  // This allows the app to work on both localhost and remote IPs
  const getDefaultServerUrl = () => {
    // If running in Electron, use localhost
    if (typeof window !== 'undefined' && (window as any).electronAPI) {
      return 'https://localhost:8443';
    }
    
    // If running in browser, use the current hostname with port 8443
    if (typeof window !== 'undefined') {
      const protocol = window.location.protocol; // Use the same protocol (http/https)
      const hostname = window.location.hostname;
      
      // If already on port 8443, use current origin
      if (window.location.port === '8443') {
        return `${protocol}//${hostname}:8443`;
      }
      
      // Otherwise, construct URL with port 8443
      return `https://${hostname}:8443`;
    }
    
    // Fallback to localhost
    return 'https://localhost:8443';
  };

  const [serverUrl, setServerUrl] = useState(getDefaultServerUrl());

  return (
    <ServerContext.Provider value={{ serverUrl, setServerUrl }}>
      {children}
    </ServerContext.Provider>
  );
};
