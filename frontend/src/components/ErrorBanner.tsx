import React from 'react'
import { AlertCircle, X } from 'lucide-react'
import type { ApiError } from '../services/api'

interface ErrorBannerProps {
  error: Error | ApiError | null
  onDismiss: () => void
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({ error, onDismiss }) => {
  if (!error) return null

  const isApiError = 'code' in error

  return (
    <div className="error-alert" role="alert">
      <AlertCircle size={20} style={{ flexShrink: 0, marginTop: '2px' }} aria-hidden="true" />
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 600, marginBottom: '2px' }}>
          {isApiError ? (error as ApiError).code : 'System Error'}
        </div>
        <div style={{ fontSize: '0.84rem' }}>{error.message}</div>
        {isApiError && (error as ApiError).requestId && (
          <div style={{ fontSize: '0.72rem', color: '#f87171', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            Request ID: {(error as ApiError).requestId}
          </div>
        )}
      </div>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss error notice"
        style={{
          background: 'transparent',
          border: 'none',
          color: '#fca5a5',
          cursor: 'pointer',
          padding: '2px',
        }}
      >
        <X size={16} aria-hidden="true" />
      </button>
    </div>
  )
}
