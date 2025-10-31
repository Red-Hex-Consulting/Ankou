import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useServerUrl } from './ServerContext';

interface User {
  id: string;
  username: string;
  createdAt: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (token: string, user: User) => void;
  logout: () => void;
  isAuthenticated: boolean;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const { serverUrl } = useServerUrl();
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check authentication status on app start
    validateAuth();
  }, []);

  useEffect(() => {
    // Set up automatic token refresh every 25 minutes
    if (!user || !token) return;

    const refreshInterval = setInterval(async () => {
      try {
        const response = await fetch(`${serverUrl}/api/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
        });
        
        if (response.ok) {
          const data = await response.json();
          setUser(data.user); // Server returns { user: User } structure
          if (data.token) {
            setToken(data.token);
            localStorage.setItem('ankou_token', data.token);
          }
        } else {
          // Token refresh failed, logout user
          console.error('Token refresh failed with status:', response.status);
          setUser(null);
          setToken(null);
        }
      } catch (error) {
        console.error('Token refresh failed:', error);
        setUser(null);
        setToken(null);
      }
    }, 20 * 60 * 1000); // 20 minutes - refresh before 1h expiration

    return () => clearInterval(refreshInterval);
  }, [user, token, serverUrl]);

  const validateAuth = async () => {
    try {
      const response = await fetch(`${serverUrl}/api/auth/validate`, {
        method: 'POST',
        credentials: 'include', // Include cookies
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
        setToken('authenticated'); // Dummy token since we use cookies
      } else {
        setUser(null);
        setToken(null);
      }
    } catch (error) {
      console.error('Auth validation failed:', error);
      setUser(null);
      setToken(null);
    } finally {
      setLoading(false);
    }
  };

  const login = (newToken: string, newUser: User) => {
    setToken(newToken); // Store the actual JWT token
    setUser(newUser);
    // Store token in localStorage for Electron
    localStorage.setItem('ankou_token', newToken);
  };

  const logout = async () => {
    try {
      // Call logout endpoint to clear server-side session
      await fetch(`${serverUrl}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setToken(null);
      setUser(null);
      localStorage.removeItem('ankou_token');
    }
  };

  const value: AuthContextType = {
    user,
    token,
    login,
    logout,
    isAuthenticated: !!user && !!token,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
