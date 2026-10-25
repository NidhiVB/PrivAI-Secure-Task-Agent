import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  ReviewPortal,
  createReviewerToken,
  REVIEWER_TOKEN_STORAGE_KEY,
} from '../components/ReviewPortal'
import * as api from '../services/api'
import type { ReviewPendingListResponse } from '../types/api'

describe('ReviewPortal Authentication & Initialization Flow', () => {
  const mockTicketsResponse: ReviewPendingListResponse = {
    tickets: [
      {
        ticket_id: 'ticket-compliance-abc12345',
        request_digest: 'sha256:testdigest123',
        submitted_at: '2026-10-25T10:00:00Z',
        expires_at: '2026-10-26T10:00:00Z',
        status: 'PENDING',
        assigned_role: 'compliance_officer',
        risk_score: 70,
        triggered_rule_ids: ['REVIEW-HEALTH-DATA'],
        decision_rationale: null,
        decided_by: null,
        decided_at: null,
      },
    ],
    total_count: 1,
  }

  beforeEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it('1. Graceful initial page load with NO token: shows unauthenticated state without errors', async () => {
    const listSpy = vi.spyOn(api, 'listPendingReviews')

    render(<ReviewPortal />)

    // Should display UNAUTHENTICATED badge immediately
    expect(screen.getByText('UNAUTHENTICATED')).toBeInTheDocument()

    // Should display helpful guidance instead of an error banner
    expect(
      screen.getByText(/No active reviewer session\. Select a role above or provide a Bearer JWT to connect\./i)
    ).toBeInTheDocument()

    // Must NOT call backend listPendingReviews with empty/missing token
    expect(listSpy).not.toHaveBeenCalled()

    // Must NOT show crypto padding or token validation error
    expect(screen.queryByText(/Token validation failed/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/Invalid crypto padding/i)).not.toBeInTheDocument()
  })

  it('2. Graceful initial page load with a MALFORMED token (invalid crypto padding): evicts bad token without crashing', async () => {
    const listSpy = vi.spyOn(api, 'listPendingReviews')

    // Seed storage with the exact malformed token that previously caused "Invalid crypto padding"
    const malformedDevToken =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXZpZXdlcl9jb21wbGlhbmNlX29mZmljZXIiLCJyb2xlcyI6WyJjb21wbGlhbmNlX29mZmljZXIiXX0.dev_signature'
    sessionStorage.setItem(REVIEWER_TOKEN_STORAGE_KEY, malformedDevToken)

    render(<ReviewPortal />)

    // Should detect malformed structure and clear it from sessionStorage
    expect(sessionStorage.getItem(REVIEWER_TOKEN_STORAGE_KEY)).toBeNull()

    // Should gracefully remain in UNAUTHENTICATED state
    expect(screen.getByText('UNAUTHENTICATED')).toBeInTheDocument()
    expect(
      screen.getByText(/No active reviewer session\. Select a role above or provide a Bearer JWT to connect\./i)
    ).toBeInTheDocument()

    // Must NOT send the poisoned token to backend
    expect(listSpy).not.toHaveBeenCalled()

    // Must NOT display an alarming raw crypto-padding error banner
    expect(screen.queryByText(/Invalid crypto padding/i)).not.toBeInTheDocument()
  })

  it('3. Initial page load with a VALID authorized token: restores session and loads queue', async () => {
    const validToken = await createReviewerToken('officer-1', 'compliance_officer')
    sessionStorage.setItem(REVIEWER_TOKEN_STORAGE_KEY, validToken)

    const listSpy = vi.spyOn(api, 'listPendingReviews').mockResolvedValue(mockTicketsResponse)

    render(<ReviewPortal />)

    // Backend must be called with the valid stored token
    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(validToken)
    })

    // Should transition to AUTHENTICATED RBAC
    await waitFor(() => {
      expect(screen.getByText('AUTHENTICATED RBAC')).toBeInTheDocument()
    })

    // Should render the active pending queue with the ticket
    expect(screen.getByText(/#ticket-c\.\.\./i)).toBeInTheDocument()
    expect(screen.getByText(/Assigned: compliance_officer/i)).toBeInTheDocument()
  })

  it('4. Quick Role Connect: acquires valid token, connects, and populates review tickets', async () => {
    const user = userEvent.setup()
    const validToken = await createReviewerToken('reviewer_compliance_officer', 'compliance_officer')

    vi.spyOn(api, 'getDemoToken').mockResolvedValue({
      token: validToken,
      role: 'compliance_officer',
      user_id: 'reviewer_compliance_officer',
    })
    const listSpy = vi.spyOn(api, 'listPendingReviews').mockResolvedValue(mockTicketsResponse)

    render(<ReviewPortal />)

    expect(screen.getByText('UNAUTHENTICATED')).toBeInTheDocument()

    // Click "Compliance Officer"
    const complianceBtn = screen.getByRole('button', { name: /Compliance Officer/i })
    await user.click(complianceBtn)

    // Should be authenticated
    await waitFor(() => {
      expect(screen.getByText('AUTHENTICATED RBAC')).toBeInTheDocument()
    })

    // Token must be stored in sessionStorage
    expect(sessionStorage.getItem(REVIEWER_TOKEN_STORAGE_KEY)).toBe(validToken)
    expect(listSpy).toHaveBeenCalledWith(validToken)

    // Ticket should appear
    expect(screen.getByText(/#ticket-c\.\.\./i)).toBeInTheDocument()

    // Disconnect should reset to unauthenticated
    const disconnectBtn = screen.getByRole('button', { name: /Disconnect/i })
    await user.click(disconnectBtn)

    expect(screen.getByText('UNAUTHENTICATED')).toBeInTheDocument()
    expect(sessionStorage.getItem(REVIEWER_TOKEN_STORAGE_KEY)).toBeNull()
  })
})
