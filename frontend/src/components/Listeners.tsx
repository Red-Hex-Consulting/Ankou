import React, { useMemo, useState } from 'react';
import { FaPlay, FaStop, FaPlus, FaTrash, FaGlobe, FaLock, FaNetworkWired, FaWifi, FaServer } from 'react-icons/fa';
import { LuRadioTower } from 'react-icons/lu';
import { useWebSocket, Listener as ListenerType } from '../hooks/useWebSocket';
import DeleteListenerModal from './DeleteListenerModal';
import './Listeners.css';

type ListenerForm = {
  name: string;
  endpoint: string;
  description: string;
};

const DEFAULT_FORM: ListenerForm = {
  name: '',
  endpoint: '/',
  description: ''
};

const escapeGraphQLString = (value: string) =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '')
    .replace(/\n/g, '\\n');

const LISTENER_FIELDS = `{
  id
  name
  type
  endpoint
  status
  description
  createdAt
}`;

const normalizeEndpoint = (endpoint: string) => {
  const trimmed = endpoint.trim();
  if (!trimmed) {
    return '/';
  }

  if (/\s/.test(trimmed)) {
    throw new Error('Endpoint cannot contain whitespace');
  }

  let normalized = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.replace(/\/+$/, '');
    if (!normalized) {
      normalized = '/';
    }
  }

  return normalized;
};

const Listeners: React.FC = () => {
  const { listeners: listenerState, isConnected, sendGraphQLQuery } = useWebSocket(true);
  const listenerList = listenerState ?? [];
  const [showAddForm, setShowAddForm] = useState(false);
  const [form, setForm] = useState<ListenerForm>({ ...DEFAULT_FORM });
  const [formError, setFormError] = useState('');
  const [globalError, setGlobalError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [listenerToDelete, setListenerToDelete] = useState<ListenerType | null>(null);

  const runningCount = useMemo(
    () => listenerList.filter((listener) => listener.status === 'running').length,
    [listenerList]
  );

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'var(--success-green)';
      case 'stopped':
        return 'var(--text-secondary)';
      case 'error':
        return 'var(--accent-red)';
      default:
        return 'var(--text-secondary)';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'https':
        return <FaLock />;
      case 'http':
        return <FaGlobe />;
      case 'tcp':
        return <FaNetworkWired />;
      case 'udp':
        return <FaWifi />;
      default:
        return <FaServer />;
    }
  };


  const resetForm = () => {
    setForm({ ...DEFAULT_FORM });
    setFormError('');
  };

  const handleAddListener = async () => {
    setFormError('');
    setGlobalError('');

    if (!form.name.trim()) {
      setFormError('Listener name is required');
      return;
    }

    let endpoint = '/';
    try {
      endpoint = normalizeEndpoint(form.endpoint);
      setForm((prev) => ({ ...prev, endpoint }));
    } catch (error) {
      setFormError(error instanceof Error ? error.message : 'Invalid endpoint');
      return;
    }

    setSubmitting(true);
    try {
      const mutation = `
        mutation {
          createListener(
            name: "${escapeGraphQLString(form.name)}",
            endpoint: "${escapeGraphQLString(endpoint)}",
            description: "${escapeGraphQLString(form.description)}"
          ) ${LISTENER_FIELDS}
        }
      `;

      const response = await sendGraphQLQuery(mutation);
      const graphqlErrors = response.errors ?? response.data?.errors;
      if (graphqlErrors && graphqlErrors.length) {
        const message = graphqlErrors[0]?.message ?? 'Failed to create listener';
        setFormError(message);
        return;
      }

      if (!response.data?.data?.createListener) {
        setFormError('Failed to create listener');
        return;
      }

      setShowAddForm(false);
      resetForm();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : 'Failed to create listener');
    } finally {
      setSubmitting(false);
    }
  };

  const handleStartStop = async (listener: ListenerType) => {
    setGlobalError('');
    const action = listener.status === 'running' ? 'stop' : 'start';

    setActionLoading((prev) => ({ ...prev, [listener.id]: true }));
    try {
      const mutation = `
        mutation {
          ${action}Listener(id: "${escapeGraphQLString(listener.id)}") ${LISTENER_FIELDS}
        }
      `;

      const response = await sendGraphQLQuery(mutation);
      const graphqlErrors = response.errors ?? response.data?.errors;
      if (graphqlErrors && graphqlErrors.length) {
        const message = graphqlErrors[0]?.message ?? `Failed to ${action} listener`;
        setGlobalError(message);
        return;
      }

      const result = response.data?.data?.[`${action}Listener`];
      if (!result) {
        setGlobalError(`Failed to ${action} listener`);
      }
    } catch (error) {
      setGlobalError(error instanceof Error ? error.message : `Failed to ${action} listener`);
    } finally {
      setActionLoading((prev) => {
        const updated = { ...prev };
        delete updated[listener.id];
        return updated;
      });
    }
  };

  const handleDeleteClick = (listener: ListenerType) => {
    setListenerToDelete(listener);
    setDeleteModalVisible(true);
  };

  const handleDeleteConfirm = async () => {
    if (!listenerToDelete) return;

    setDeleteModalVisible(false);
    setGlobalError('');
    setActionLoading((prev) => ({ ...prev, [listenerToDelete.id]: true }));
    
    try {
      const mutation = `
        mutation {
          deleteListener(id: "${escapeGraphQLString(listenerToDelete.id)}")
        }
      `;

      const response = await sendGraphQLQuery(mutation);
      const graphqlErrors = response.errors ?? response.data?.errors;
      if (graphqlErrors && graphqlErrors.length) {
        const message = graphqlErrors[0]?.message ?? 'Failed to delete listener';
        setGlobalError(message);
        return;
      }

      if (!response.data?.data?.deleteListener) {
        setGlobalError('Failed to delete listener');
      }
    } catch (error) {
      setGlobalError(error instanceof Error ? error.message : 'Failed to delete listener');
    } finally {
      setActionLoading((prev) => {
        const updated = { ...prev };
        delete updated[listenerToDelete.id];
        return updated;
      });
      setListenerToDelete(null);
    }
  };

  const handleDeleteCancel = () => {
    setDeleteModalVisible(false);
    setListenerToDelete(null);
  };

  return (
    <div className="listeners-container">
      <div className="listeners-search">
        <div className="listeners-stats">
          <LuRadioTower className="stats-icon" />
          <span className="stats-text">{listenerList.length} Total</span>
          <span className="stats-text">•</span>
          <span className="stats-text">{runningCount} Running</span>
        </div>
        <button
          className="listeners-add-btn"
          onClick={() => {
            setShowAddForm(true);
            setFormError('');
            setGlobalError('');
          }}
          disabled={submitting}
        >
          <FaPlus /> Add Listener
        </button>
      </div>

      {globalError && (
        <div
          style={{
            margin: '12px 0',
            color: 'var(--accent-red)',
            fontSize: '0.85rem'
          }}
        >
          {globalError}
        </div>
      )}

      {showAddForm && (
        <div className="listeners-add-form">
          <h3>Add New Listener</h3>
          <div className="listeners-form-row">
            <input
              type="text"
              placeholder="Name *"
              value={form.name}
              onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
            />
            <select value="https" disabled>
              <option value="https">HTTPS</option>
            </select>
          </div>
          <div className="listeners-form-row">
            <input
              type="text"
              placeholder="Endpoint * (e.g. /beacon)"
              value={form.endpoint}
              onChange={(e) => setForm((prev) => ({ ...prev, endpoint: e.target.value }))}
            />
          </div>
          <div className="listeners-form-row">
            <textarea
              placeholder="Description"
              value={form.description}
              onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
            />
          </div>
          {formError && (
            <div
              style={{
                marginTop: '8px',
                color: 'var(--accent-red)',
                fontSize: '0.8rem'
              }}
            >
              {formError}
            </div>
          )}
          <div className="listeners-form-actions">
            <button className="listeners-save-btn" onClick={handleAddListener} disabled={submitting}>
              {submitting ? 'Saving...' : 'Save'}
            </button>
            <button
              className="listeners-cancel-btn"
              onClick={() => {
                setShowAddForm(false);
                resetForm();
              }}
              disabled={submitting}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="listeners-table">
        <div className="listeners-table-header">
          <div>Name</div>
          <div>Type</div>
          <div>Endpoint</div>
          <div>Status</div>
          <div>Actions</div>
        </div>
        <div className="listeners-table-body">
          {listenerList.length === 0 ? (
            <div className="empty-state">
              <FaServer className="empty-icon" />
              <p>{isConnected ? 'No listeners configured' : 'Connecting...'}</p>
            </div>
          ) : (
            listenerList.map((listener) => {
              const isBusy = !!actionLoading[listener.id];
              const isRunning = listener.status === 'running';

              return (
                <div key={listener.id} className="listener-row">
                  <div className="listener-name-cell">
                    <div className="listener-icon">{getTypeIcon(listener.type)}</div>
                    <div className="listener-name-info">
                      <div className="listener-name">{listener.name}</div>
                      {listener.description && (
                        <div className="listener-description">{listener.description}</div>
                      )}
                    </div>
                  </div>
                  <div>
                    <span className="listener-type-badge">{listener.type.toUpperCase()}</span>
                  </div>
                  <div className="listener-address">
                    <div>
                      {listener.endpoint}
                    </div>
                  </div>
                  <div className="listener-col-status">
                    <div
                      className="status-indicator"
                      style={{ backgroundColor: getStatusColor(listener.status) }}
                    />
                    <span className="status-text">{listener.status}</span>
                  </div>
                  <div className="listener-col-actions">
                    <button
                      className={`listener-action-btn ${isRunning ? 'stop' : 'start'}`}
                      onClick={() => handleStartStop(listener)}
                      title={isRunning ? 'Stop' : 'Start'}
                      disabled={isBusy}
                    >
                      {isRunning ? <FaStop /> : <FaPlay />}
                    </button>
                    <button
                      className="listener-action-btn delete"
                      onClick={() => handleDeleteClick(listener)}
                      title="Delete"
                      disabled={isBusy}
                    >
                      <FaTrash />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      <DeleteListenerModal
        isVisible={deleteModalVisible}
        listenerName={listenerToDelete?.name || ''}
        onConfirm={handleDeleteConfirm}
        onCancel={handleDeleteCancel}
      />
    </div>
  );
};

export default Listeners;
