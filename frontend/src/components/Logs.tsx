import React, { useState, useEffect, useCallback } from 'react';
import { FaFileAlt, FaSearch, FaSync, FaTerminal, FaReply, FaServer, FaRobot, FaLock, FaShieldAlt, FaFile } from 'react-icons/fa';
import { useWebSocket } from '../hooks/useWebSocket';
import LoadingSpinner from './LoadingSpinner';
import './Logs.css';

interface LogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  source: string;
}

const Logs: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [totalCount, setTotalCount] = useState(0);
  const [offset, setOffset] = useState(0);
  const [isSearching, setIsSearching] = useState(false);
  const PAGE_SIZE = 50;
  const { sendGraphQLQuery, isConnected } = useWebSocket();

  useEffect(() => {
    if (isConnected) {
      loadLogs(true);
    }
  }, [isConnected]);

  // Handle search with debounce
  useEffect(() => {
    const delaySearch = setTimeout(() => {
      if (searchTerm) {
        performSearch();
      } else {
        // Clear search, return to paginated view
        if (isSearching) {
          setIsSearching(false);
          setOffset(0);
          loadLogs(true);
        }
      }
    }, 300); // 300ms debounce

    return () => clearTimeout(delaySearch);
  }, [searchTerm]);

  const loadLogs = async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
        setOffset(0);
      } else {
        setLoadingMore(true);
      }
      
      const currentOffset = isRefresh ? 0 : offset;
      
      const query = `
        query {
          logs(limit: ${PAGE_SIZE}, offset: ${currentOffset}) {
            id
            timestamp
            level
            message
            source
          }
          logsCount
        }
      `;

      const response = await sendGraphQLQuery(query);
      
      if (response.data?.data?.logs) {
        const newLogs = response.data.data.logs;
        const count = response.data.data.logsCount || 0;
        
        if (isRefresh) {
          setLogs(newLogs);
          setOffset(PAGE_SIZE);
        } else {
          setLogs([...logs, ...newLogs]);
          setOffset(offset + PAGE_SIZE);
        }
        
        setTotalCount(count);
      }
    } catch (error) {
      console.error('Error loading logs:', error);
    } finally {
      setRefreshing(false);
      setLoadingMore(false);
      setLoading(false);
    }
  };

  const performSearch = async () => {
    try {
      setLoading(true);
      setIsSearching(true);
      
      const query = `
        query {
          logs(search: "${searchTerm.replace(/"/g, '\\"')}") {
            id
            timestamp
            level
            message
            source
          }
          logsCount(search: "${searchTerm.replace(/"/g, '\\"')}")
        }
      `;

      const response = await sendGraphQLQuery(query);
      
      if (response.data?.data?.logs) {
        setLogs(response.data.data.logs);
        setTotalCount(response.data.data.logsCount || 0);
      }
    } catch (error) {
      console.error('Error searching logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = useCallback(async () => {
    if (refreshing) return;
    if (isSearching) {
      performSearch();
    } else {
      loadLogs(true);
    }
  }, [refreshing, isSearching, searchTerm]);

  const handleLoadMore = useCallback(() => {
    if (!loadingMore && !isSearching) {
      loadLogs(false);
    }
  }, [loadingMore, isSearching, logs, offset]);

  const getLevelClass = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error':
        return 'error';
      case 'warn':
      case 'warning':
        return 'warn';
      case 'info':
        return 'info';
      case 'debug':
        return 'debug';
      default:
        return 'info';
    }
  };

  const getSourceIcon = (source: string) => {
    const iconStyle = { fontSize: '14px', marginRight: '6px' };
    
    switch (source.toLowerCase()) {
      case 'command':
        return <FaTerminal style={{ ...iconStyle, color: '#3b82f6' }} />; // Blue
      case 'response':
        return <FaReply style={{ ...iconStyle, color: '#10b981' }} />; // Green
      case 'server':
        return <FaServer style={{ ...iconStyle, color: '#8b5cf6' }} />; // Purple
      case 'agent':
        return <FaRobot style={{ ...iconStyle, color: '#f59e0b' }} />; // Orange
      case 'auth':
        return <FaLock style={{ ...iconStyle, color: '#ef4444' }} />; // Red
      case 'security':
        return <FaShieldAlt style={{ ...iconStyle, color: '#06b6d4' }} />; // Cyan
      default:
        return <FaFile style={{ ...iconStyle, color: '#6b7280' }} />; // Gray
    }
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3
      });
    } catch {
      return timestamp;
    }
  };

  if (!isConnected) {
    return (
      <div className="logs-container">
        <div className="logs-loading">
          <LoadingSpinner size={20} />
          Connecting...
        </div>
      </div>
    );
  }

  if (loading && logs.length === 0) {
    return (
      <div className="logs-container">
        <div className="logs-loading">
          <LoadingSpinner size={20} />
          Loading logs...
        </div>
      </div>
    );
  }

  return (
    <div className="logs-container">
      {/* Header */}
      <div className="logs-search">
        <div className="logs-search-left">
          <div className="search-input-container">
            <FaSearch className="search-icon" />
            <input
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
          </div>

          <div className="logs-stats">
            <FaFileAlt className="stats-icon" />
            <span className="stats-text">
              {isSearching ? `${logs.length} results` : `${logs.length} of ${totalCount} logs`}
              {refreshing && (
                <span style={{ marginLeft: '8px', color: 'var(--text-secondary)', fontSize: '11px' }}>
                  (updating...)
                </span>
              )}
              {isSearching && (
                <span style={{ marginLeft: '8px', color: 'var(--accent-blue)', fontSize: '11px' }}>
                  (searching)
                </span>
              )}
            </span>
          </div>
        </div>

        <button
          className="logs-refresh-btn"
          onClick={handleRefresh}
          disabled={refreshing}
        >
          <FaSync style={{ fontSize: '12px' }} />
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {/* Table */}
      <div className="logs-table">
        <div className="logs-table-header">
          <div>Time</div>
          <div>Message</div>
          <div>Source</div>
          <div>Level</div>
        </div>
        
        <div className="logs-table-body">
          {logs.length === 0 ? (
            <div className="empty-state">
              <FaFileAlt className="empty-icon" />
              <div>{isSearching ? 'No logs match your search' : 'No logs found'}</div>
            </div>
          ) : (
            <>
              {logs.map((log) => (
                <div key={log.id} className="log-row">
                  <div className="log-timestamp">
                    {formatTimestamp(log.timestamp)}
                  </div>
                  <div className="log-message">
                    {log.message}
                  </div>
                  <div className="log-source">
                    {getSourceIcon(log.source)}
                    <span style={{ textTransform: 'capitalize' }}>
                      {log.source}
                    </span>
                  </div>
                  <div className={`log-level ${getLevelClass(log.level)}`}>
                    {log.level.toUpperCase()}
                  </div>
                </div>
              ))}
              
              {!isSearching && logs.length < totalCount && (
                <div className="logs-footer">
                  Showing {logs.length} of {totalCount} logs
                  <button 
                    className="logs-load-more" 
                    onClick={handleLoadMore}
                    disabled={loadingMore}
                  >
                    {loadingMore ? 'Loading...' : 'Load More Logs'}
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Logs;
