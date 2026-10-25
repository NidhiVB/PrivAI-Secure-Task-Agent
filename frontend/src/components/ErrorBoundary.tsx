import React, { Component, ErrorInfo, ReactNode } from 'react'
import { AlertOctagon, RotateCcw } from 'lucide-react'

interface Props {
  children: ReactNode
  fallbackTitle?: string
  onReset?: () => void
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an unhandled render error:', error, errorInfo)
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null })
    if (this.props.onReset) {
      this.props.onReset()
    }
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div
          className="card"
          role="alert"
          aria-live="assertive"
          style={{
            margin: '1.5rem 0',
            padding: '1.5rem',
            background: 'var(--color-block-bg, rgba(239, 68, 68, 0.08))',
            borderColor: 'var(--color-block-border, rgba(239, 68, 68, 0.35))',
            borderRadius: 'var(--radius-md, 8px)',
            color: 'var(--text-main, #f8fafc)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <AlertOctagon size={22} color="var(--color-block, #ef4444)" aria-hidden="true" />
            <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-block, #ef4444)' }}>
              {this.props.fallbackTitle || 'Component Rendering Error'}
            </h3>
          </div>

          <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--text-muted, #94a3b8)', lineHeight: 1.5 }}>
            A rendering error occurred while displaying this view. The application captured this state to prevent a
            blank screen.
          </p>

          {this.state.error && (
            <div
              style={{
                fontFamily: 'var(--font-mono, monospace)',
                fontSize: '0.78rem',
                background: 'rgba(0, 0, 0, 0.35)',
                padding: '0.65rem 0.85rem',
                borderRadius: 'var(--radius-sm, 4px)',
                color: '#fca5a5',
                overflowX: 'auto',
                border: '1px solid rgba(239, 68, 68, 0.2)',
              }}
            >
              {this.state.error.name}: {this.state.error.message}
            </div>
          )}

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.25rem' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={this.handleReset}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                fontSize: '0.82rem',
                padding: '0.45rem 1rem',
              }}
            >
              <RotateCcw size={14} aria-hidden="true" />
              Reset View & Try Again
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
