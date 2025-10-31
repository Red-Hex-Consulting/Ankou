import React, { useState, useMemo } from 'react';
import { FaUserSecret, FaUser, FaCalendarAlt, FaSearch, FaPlus, FaTrash } from 'react-icons/fa';
import { useWebSocket } from '../hooks/useWebSocket';

interface User {
  id: string;
  username: string;
  created_at: string;
}

const Operators: React.FC = () => {
  const { users, isConnected, sendGraphQLQuery } = useWebSocket(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [showAddModal, setShowAddModal] = useState(false);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [newUser, setNewUser] = useState({ username: '', password: '', registrationKey: '' });
  const [revokeKey, setRevokeKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const filteredUsers = useMemo(() => {
    if (!users) return [];
    return users.filter(user => 
      user.username.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [users, searchTerm]);

  const userStats = useMemo(() => {
    if (!users) return { total: 0 };
    return { total: users.length };
  }, [users]);

  const formatDate = (dateString: string) => {
    if (!dateString) return 'Unknown';
    
    const date = new Date(dateString);
    
    // Check if date is valid
    if (isNaN(date.getTime())) {
      return 'Unknown';
    }
    
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleAddOperator = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const mutation = `
        mutation {
          createUser(
            username: "${newUser.username}",
            password: "${newUser.password}",
            registrationKey: "${newUser.registrationKey}"
          ) {
            id
            username
            created_at
          }
        }
      `;

      const response = await sendGraphQLQuery(mutation);
      
      if (response.data?.data?.createUser) {
        setShowAddModal(false);
        setNewUser({ username: '', password: '', registrationKey: '' });
      } else {
        setError('Failed to create operator');
      }
    } catch (err) {
      setError('Error creating operator');
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeOperator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;

    setLoading(true);
    setError('');

    try {
      const mutation = `
        mutation {
          revokeUser(
            userId: "${selectedUser.id}",
            registrationKey: "${revokeKey}"
          ) {
            success
          }
        }
      `;

      const response = await sendGraphQLQuery(mutation);
      
      if (response.data?.data?.revokeUser?.success) {
        setShowRevokeModal(false);
        setSelectedUser(null);
        setRevokeKey('');
      } else {
        setError('Failed to revoke operator');
      }
    } catch (err) {
      setError('Error revoking operator');
    } finally {
      setLoading(false);
    }
  };

  if (!isConnected) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100%',
        color: 'var(--text-secondary)'
      }}>
        <div style={{ textAlign: 'center' }}>
          <FaUserSecret style={{ fontSize: '2rem', marginBottom: '1rem', opacity: 0.5 }} />
          <div>Connecting...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="operators-container">
      <div className="operators-search">
        <div className="search-input-container">
          <FaSearch className="search-icon" />
          <input
            type="text"
            placeholder="Search operators..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div className="operators-stats">
            <FaUserSecret className="stats-icon" />
            <span className="stats-text">
              {userStats.total} Operator{userStats.total !== 1 ? 's' : ''}
            </span>
          </div>
          
          <button
            onClick={() => setShowAddModal(true)}
            className="add-operator-btn"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 16px',
              backgroundColor: 'var(--accent-red)',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: '500',
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--accent-red-hover)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--accent-red)';
            }}
          >
            <FaPlus />
            Add Operator
          </button>
        </div>
      </div>

      {/* Users Table */}
      <div className="operators-table">
        <div className="operators-table-header">
          <div className="operator-col-name">Operator</div>
          <div className="operator-col-joined">Joined</div>
          <div className="operator-col-actions">Actions</div>
        </div>
        
        <div className="operators-table-body">
          {filteredUsers.length === 0 ? (
            <div className="empty-state">
              <FaUser className="empty-icon" />
              <div>No operators found</div>
            </div>
          ) : (
            filteredUsers.map((user) => (
              <div key={user.id} className="operator-row">
                <div className="operator-name-cell">
                  <FaUserSecret className="operator-icon" />
                  <div className="operator-name-info">
                    <div className="operator-name">{user.username}</div>
                  </div>
                </div>
                <div className="operator-joined">
                  <FaCalendarAlt className="operator-date-icon" />
                  <span>{formatDate(user.created_at)}</span>
                </div>
                <div className="operator-actions">
                  <button
                    onClick={() => {
                      setSelectedUser(user);
                      setShowRevokeModal(true);
                    }}
                    className="revoke-btn"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '8px 16px',
                      backgroundColor: 'var(--accent-red)',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      fontSize: '12px',
                      fontWeight: '500',
                      transition: 'all 0.2s ease'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = 'var(--accent-red-hover)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = 'var(--accent-red)';
                    }}
                  >
                    <FaTrash />
                    Revoke
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Add Operator Modal */}
      {showAddModal && (
        <div className="modal-overlay" style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div className="modal-content" style={{
            backgroundColor: 'var(--bg-secondary)',
            borderRadius: '8px',
            padding: '24px',
            width: '400px',
            maxWidth: '90vw'
          }}>
            <h3 style={{ margin: '0 0 20px 0', color: 'var(--text-primary)' }}>Add New Operator</h3>
            
            <form onSubmit={handleAddOperator}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-primary)', fontSize: '14px' }}>
                  Username
                </label>
                <input
                  type="text"
                  value={newUser.username}
                  onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                  required
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontSize: '14px'
                  }}
                />
              </div>
              
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-primary)', fontSize: '14px' }}>
                  Password
                </label>
                <input
                  type="password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  required
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontSize: '14px'
                  }}
                />
              </div>
              
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-primary)', fontSize: '14px' }}>
                  Registration Key
                </label>
                <input
                  type="password"
                  value={newUser.registrationKey}
                  onChange={(e) => setNewUser({ ...newUser, registrationKey: e.target.value })}
                  required
                  placeholder="Enter server registration key"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontSize: '14px'
                  }}
                />
              </div>
              
              {error && (
                <div style={{ color: 'var(--accent-red)', marginBottom: '16px', fontSize: '14px' }}>
                  {error}
                </div>
              )}
              
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => {
                    setShowAddModal(false);
                    setNewUser({ username: '', password: '', registrationKey: '' });
                    setError('');
                  }}
                  style={{
                    padding: '8px 16px',
                    backgroundColor: 'transparent',
                    color: 'var(--text-secondary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '14px'
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    padding: '8px 16px',
                    backgroundColor: 'var(--accent-red)',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: loading ? 'not-allowed' : 'pointer',
                    fontSize: '14px',
                    opacity: loading ? 0.6 : 1
                  }}
                >
                  {loading ? 'Creating...' : 'Create Operator'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revoke Operator Modal */}
      {showRevokeModal && selectedUser && (
        <div className="modal-overlay" style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div className="modal-content" style={{
            backgroundColor: 'var(--bg-secondary)',
            borderRadius: '8px',
            padding: '24px',
            width: '400px',
            maxWidth: '90vw'
          }}>
            <h3 style={{ margin: '0 0 20px 0', color: 'var(--text-primary)' }}>
              Revoke Operator: {selectedUser.username}
            </h3>
            
            <form onSubmit={handleRevokeOperator}>
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-primary)', fontSize: '14px' }}>
                  Registration Key
                </label>
                <input
                  type="password"
                  value={revokeKey}
                  onChange={(e) => setRevokeKey(e.target.value)}
                  required
                  placeholder="Enter registration key to confirm"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontSize: '14px'
                  }}
                />
              </div>
              
              {error && (
                <div style={{ color: 'var(--accent-red)', marginBottom: '16px', fontSize: '14px' }}>
                  {error}
                </div>
              )}
              
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => {
                    setShowRevokeModal(false);
                    setSelectedUser(null);
                    setRevokeKey('');
                    setError('');
                  }}
                  style={{
                    padding: '8px 16px',
                    backgroundColor: 'transparent',
                    color: 'var(--text-secondary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '14px'
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    padding: '8px 16px',
                    backgroundColor: 'var(--accent-red)',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: loading ? 'not-allowed' : 'pointer',
                    fontSize: '14px',
                    opacity: loading ? 0.6 : 1
                  }}
                >
                  {loading ? 'Revoking...' : 'Revoke Access'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Operators;
