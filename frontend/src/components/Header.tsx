import { ShieldCheck, Cpu, KeyRound, Check, X } from 'lucide-react'
import React, { useState } from 'react'
import type { HealthResponse } from '../types/api'
import { getTeamAccessKey, setTeamAccessKey } from '../services/api'

interface HeaderProps {
  health: HealthResponse | null
  healthLoading: boolean
  onTeamKeyChange?: () => void
}

export const Header: React.FC<HeaderProps> = ({ health, healthLoading, onTeamKeyChange }) => {
  const isOnline = health?.status === 'ok'
  const [currentKey, setCurrentKey] = useState<string>(getTeamAccessKey())
  const [showPrompt, setShowPrompt] = useState<boolean>(false)
  const [inputVal, setInputVal] = useState<string>('')

  const handleOpenPrompt = () => {
    setInputVal(currentKey)
    setShowPrompt(true)
  }

  const handleSaveKey = (e: React.FormEvent) => {
    e.preventDefault()
    setTeamAccessKey(inputVal)
    setCurrentKey(inputVal.trim())
    setShowPrompt(false)
    if (onTeamKeyChange) onTeamKeyChange()
  }

  return (
    <header className="app-header" role="banner">
      <div className="brand-section">
        <div className="brand-logo" aria-hidden="true">
          <ShieldCheck size={28} />
        </div>
        <div>
          <h1 className="brand-title">PrivAI</h1>
          <p className="brand-subtitle">Context-Aware AI Privacy Firewall & Sanitization Engine</p>
        </div>
      </div>

      <div className="header-meta">
        {/* Team Access Passkey Indicator */}
        <button
          type="button"
          className="status-badge"
          onClick={handleOpenPrompt}
          title="Team Access Passkey for Shared Instances"
          style={{
            cursor: 'pointer',
            border: '1px solid rgba(139, 92, 246, 0.3)',
            background: currentKey ? 'rgba(139, 92, 246, 0.15)' : 'rgba(30, 41, 59, 0.7)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem',
            color: currentKey ? '#c4b5fd' : '#94a3b8',
          }}
          aria-label="Configure team access passkey"
        >
          <KeyRound size={14} color={currentKey ? '#a78bfa' : '#64748b'} aria-hidden="true" />
          <span>{currentKey ? 'Team Access: Active' : 'Set Team Key'}</span>
        </button>

        <div
          className="status-badge"
          title={isOnline ? 'Connected to backend firewall' : 'Backend connection unavailable'}
          aria-label={isOnline ? 'System status: online' : 'System status: offline'}
        >
          <span
            className={`status-dot ${isOnline ? 'online' : 'offline'}`}
            aria-hidden="true"
          />
          {healthLoading ? (
            <span>Checking...</span>
          ) : isOnline ? (
            <span>Firewall Active ({health?.provider_mode || 'mock'})</span>
          ) : (
            <span>Firewall Disconnected</span>
          )}
        </div>

        <div className="status-badge" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <Cpu size={14} color="#06b6d4" aria-hidden="true" />
          <span>Policy: {health?.policy_loaded ? 'policy-v1 (Loaded)' : 'Unloaded'}</span>
        </div>
      </div>

      {/* Team Access Modal */}
      {showPrompt && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
          onClick={() => setShowPrompt(false)}
        >
          <div
            style={{
              background: '#0f172a',
              border: '1px solid #334155',
              borderRadius: '0.75rem',
              padding: '1.75rem',
              width: '100%',
              maxWidth: '440px',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <KeyRound size={20} color="#8b5cf6" />
                <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#f8fafc', fontWeight: 600 }}>
                  Team Access Passkey
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowPrompt(false)}
                style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '0.25rem' }}
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>

            <p style={{ color: '#94a3b8', fontSize: '0.875rem', lineHeight: 1.5, margin: '0 0 1.25rem 0' }}>
              Enter the authorized team passkey to access this shared PrivAI instance. This passkey is sent as an authorization header to the backend firewall.
            </p>

            <form onSubmit={handleSaveKey}>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.35rem', fontWeight: 500 }}>
                  Team Passkey
                </label>
                <input
                  type="password"
                  value={inputVal}
                  onChange={(e) => setInputVal(e.target.value)}
                  placeholder="e.g. privai-team-2026"
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.85rem',
                    background: '#1e293b',
                    border: '1px solid #475569',
                    borderRadius: '0.375rem',
                    color: '#f8fafc',
                    fontSize: '0.9rem',
                    boxSizing: 'border-box',
                  }}
                  autoFocus
                />
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('')
                    setTeamAccessKey('')
                    setCurrentKey('')
                    setShowPrompt(false)
                    if (onTeamKeyChange) onTeamKeyChange()
                  }}
                  style={{
                    padding: '0.55rem 1rem',
                    background: 'transparent',
                    border: '1px solid #475569',
                    borderRadius: '0.375rem',
                    color: '#94a3b8',
                    cursor: 'pointer',
                    fontSize: '0.85rem',
                  }}
                >
                  Clear Key
                </button>
                <button
                  type="submit"
                  style={{
                    padding: '0.55rem 1.25rem',
                    background: '#8b5cf6',
                    border: 'none',
                    borderRadius: '0.375rem',
                    color: '#ffffff',
                    fontWeight: 600,
                    cursor: 'pointer',
                    fontSize: '0.85rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                  }}
                >
                  <Check size={16} />
                  Save & Apply
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </header>
  )
}

