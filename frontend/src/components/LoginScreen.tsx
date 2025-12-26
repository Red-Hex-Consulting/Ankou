import React, { useState } from 'react';
import { FaLock, FaUser, FaKey, FaEye, FaEyeSlash } from 'react-icons/fa';
import { useServerUrl } from '../contexts/ServerContext';

interface LoginScreenProps {
  onLogin: (token: string, user: any) => void;
}

const LoginScreen: React.FC<LoginScreenProps> = ({ onLogin }) => {
  const { serverUrl, setServerUrl } = useServerUrl();
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [rememberMe, setRememberMe] = useState(true); // Default to true for convenience
  
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    registrationKey: '',
    serverUrl: serverUrl
  });

  // Load saved credentials on mount
  React.useEffect(() => {
    const savedUsername = localStorage.getItem('ankou_remembered_username');
    const savedServerUrl = localStorage.getItem('ankou_remembered_serverUrl');
    
    if (savedUsername) {
      setFormData(prev => ({ ...prev, username: savedUsername }));
    }
    if (savedServerUrl) {
      setFormData(prev => ({ ...prev, serverUrl: savedServerUrl }));
      setServerUrl(savedServerUrl);
    }
  }, [setServerUrl]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const body = isLogin 
        ? { username: formData.username, password: formData.password }
        : { username: formData.username, password: formData.password, registrationKey: formData.registrationKey };

      const response = await fetch(`${formData.serverUrl}${endpoint}`, {
        method: 'POST',
        credentials: 'include', // Include cookies
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Authentication failed');
      }

      const data = await response.json();
      // Update server URL in context
      setServerUrl(formData.serverUrl);
      
      // Save credentials if remember me is checked
      if (rememberMe) {
        localStorage.setItem('ankou_remembered_username', formData.username);
        localStorage.setItem('ankou_remembered_serverUrl', formData.serverUrl);
      } else {
        // Clear saved credentials if remember me is unchecked
        localStorage.removeItem('ankou_remembered_username');
        localStorage.removeItem('ankou_remembered_serverUrl');
      }
      
      onLogin(data.token, data.user); // Use actual JWT token from server
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0f0f0f 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      overflow: 'hidden'
    }}>
      {/* Background decorative elements */}
      <div style={{
        position: 'absolute',
        top: '-50%',
        left: '-50%',
        width: '200%',
        height: '200%',
        background: 'radial-gradient(circle at 20% 80%, rgba(255, 107, 107, 0.1) 0%, transparent 50%), radial-gradient(circle at 80% 20%, rgba(255, 107, 107, 0.05) 0%, transparent 50%)',
        animation: 'float 20s ease-in-out infinite'
      }} />
      <div style={{
        position: 'absolute',
        top: '10%',
        right: '10%',
        width: '300px',
        height: '300px',
        background: 'radial-gradient(circle, rgba(255, 107, 107, 0.1) 0%, transparent 70%)',
        borderRadius: '50%',
        animation: 'pulse 4s ease-in-out infinite'
      }} />
      <div style={{
        position: 'absolute',
        bottom: '20%',
        left: '15%',
        width: '200px',
        height: '200px',
        background: 'radial-gradient(circle, rgba(255, 107, 107, 0.08) 0%, transparent 70%)',
        borderRadius: '50%',
        animation: 'float 15s ease-in-out infinite reverse'
      }} />
      <div style={{
        background: 'linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%)',
        padding: '1.5rem',
        borderRadius: '16px',
        boxShadow: '0 15px 40px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.1)',
        width: 'min(380px, 85vw)',
        maxHeight: '85vh',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        backdropFilter: 'blur(10px)',
        position: 'relative',
        overflow: 'auto',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header */}
        <div style={{
          textAlign: 'center',
          marginBottom: '0'
        }}>
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
            marginBottom: '1rem'
          }}>
            <img src="./logo.png" alt="Ankou Logo" style={{ width: '200px', height: '200px' }} />
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div style={{
            background: 'var(--accent-red)',
            color: 'white',
            padding: '0.75rem',
            borderRadius: '4px',
            marginBottom: '1rem',
            fontSize: '0.9rem'
          }}>
            {error}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit}>
          {/* Username */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{
              display: 'block',
              color: 'var(--text-primary)',
              marginBottom: '0.5rem',
              fontSize: '0.9rem',
              fontFamily: "'Pirata One', cursive"
            }}>
              Username
            </label>
            <div style={{ position: 'relative' }}>
              <FaUser style={{
                position: 'absolute',
                left: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-secondary)',
                fontSize: '0.9rem'
              }} />
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
                style={{
                  width: '100%',
                  padding: '0.75rem 0.75rem 0.75rem 2.5rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  color: 'var(--text-primary)',
                  fontSize: '0.9rem',
                  fontFamily: "'Pirata One', cursive",
                  outline: 'none'
                }}
                placeholder="Enter username"
              />
            </div>
          </div>

          {/* Password */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{
              display: 'block',
              color: 'var(--text-primary)',
              marginBottom: '0.5rem',
              fontSize: '0.9rem',
              fontFamily: "'Pirata One', cursive"
            }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <FaLock style={{
                position: 'absolute',
                left: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-secondary)',
                fontSize: '0.9rem'
              }} />
              <input
                type={showPassword ? 'text' : 'password'}
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                required
                style={{
                  width: '100%',
                  padding: '0.75rem 2.5rem 0.75rem 2.5rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  color: 'var(--text-primary)',
                  fontSize: '0.9rem',
                  fontFamily: "'Pirata One', cursive",
                  outline: 'none'
                }}
                placeholder="Enter password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.9rem'
                }}
              >
                {showPassword ? <FaEyeSlash /> : <FaEye />}
              </button>
            </div>
          </div>

          {/* Server URL */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{
              display: 'block',
              color: 'var(--text-primary)',
              marginBottom: '0.5rem',
              fontSize: '0.9rem',
              fontFamily: "'Pirata One', cursive"
            }}>
              Server URL
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type="text"
                name="serverUrl"
                value={formData.serverUrl}
                onChange={handleInputChange}
                required
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  color: 'var(--text-primary)',
                  fontSize: '0.9rem',
                  fontFamily: "'Pirata One', cursive",
                  outline: 'none'
                }}
                placeholder="https://localhost:8443"
              />
            </div>
          </div>

          {/* Registration Key (only for registration) */}
          {!isLogin && (
            <div style={{ marginBottom: '1rem' }}>
              <label style={{
                display: 'block',
                color: 'var(--text-primary)',
                marginBottom: '0.5rem',
                fontSize: '0.9rem',
                fontFamily: "'Pirata One', cursive"
              }}>
                Registration Key
              </label>
              <div style={{ position: 'relative' }}>
                <FaKey style={{
                  position: 'absolute',
                  left: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-secondary)',
                  fontSize: '0.9rem'
                }} />
                <input
                  type="text"
                  name="registrationKey"
                  value={formData.registrationKey}
                  onChange={handleInputChange}
                  required
                  style={{
                    width: '100%',
                    padding: '0.75rem 0.75rem 0.75rem 2.5rem',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontSize: '0.9rem',
                    fontFamily: "'Pirata One', cursive",
                    outline: 'none'
                  }}
                  placeholder="Enter registration key"
                />
              </div>
            </div>
          )}

          {/* Remember Me Checkbox (only for login) */}
          {isLogin && (
            <div style={{ 
              marginBottom: '1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <input
                type="checkbox"
                id="rememberMe"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                style={{
                  cursor: 'pointer',
                  width: '16px',
                  height: '16px',
                  accentColor: 'var(--accent-red)'
                }}
              />
              <label 
                htmlFor="rememberMe"
                style={{
                  color: 'var(--text-secondary)',
                  fontSize: '0.85rem',
                  fontFamily: "'Pirata One', cursive",
                  cursor: 'pointer',
                  userSelect: 'none'
                }}
              >
                Remember username and server
              </label>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.75rem',
              background: loading ? 'var(--text-secondary)' : 'var(--accent-red)',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              fontSize: '0.9rem',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              marginBottom: '1rem'
            }}
          >
            {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
          </button>

          {/* Toggle Login/Register */}
          <div style={{
            textAlign: 'center',
            fontSize: '0.9rem',
            color: 'var(--text-secondary)'
          }}>
            {isLogin ? "Don't have an account? " : "Already have an account? "}
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setError('');
                // Keep username and serverUrl if remembered, only clear password and registration key
                const savedUsername = localStorage.getItem('ankou_remembered_username') || '';
                const savedServerUrl = localStorage.getItem('ankou_remembered_serverUrl') || serverUrl;
                setFormData({ 
                  username: savedUsername, 
                  password: '', 
                  registrationKey: '', 
                  serverUrl: savedServerUrl 
                });
              }}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--accent-red)',
                cursor: 'pointer',
                textDecoration: 'underline'
              }}
            >
              {isLogin ? 'Register' : 'Sign In'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginScreen;
