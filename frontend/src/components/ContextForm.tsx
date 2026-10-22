import React from 'react'
import { Sliders, Shield, Tag, UserCheck, Compass } from 'lucide-react'
import type {
  ContextClassification,
  ContextDataSubject,
  ContextModel,
  ContextPurpose,
  Destination,
} from '../types/api'

interface ContextFormProps {
  destination: Destination
  context: ContextModel
  onDestinationChange: (dest: Destination) => void
  onContextChange: (ctx: ContextModel) => void
  disabled?: boolean
}

export const ContextForm: React.FC<ContextFormProps> = ({
  destination,
  context,
  onDestinationChange,
  onContextChange,
  disabled = false,
}) => {
  const handlePurposeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onContextChange({
      ...context,
      purpose: e.target.value as ContextPurpose,
    })
  }

  const handleDataSubjectChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onContextChange({
      ...context,
      data_subject: e.target.value as ContextDataSubject,
    })
  }

  const handleClassificationChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onContextChange({
      ...context,
      classification: e.target.value as ContextClassification,
    })
  }

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">
          <Sliders size={18} color="#06b6d4" aria-hidden="true" />
          Execution Context & Destination
        </h2>
      </div>

      <div className="context-row">
        {/* Destination Provider */}
        <div className="form-group">
          <label htmlFor="destination-select" className="form-label">
            <Compass size={13} style={{ display: 'inline', marginRight: '4px' }} aria-hidden="true" />
            AI Destination
          </label>
          <select
            id="destination-select"
            className="form-select"
            value={destination}
            onChange={(e) => onDestinationChange(e.target.value as Destination)}
            disabled={disabled}
          >
            <option value="mock">mock (Local Mock Adapter)</option>
            <option value="groq">groq (External Groq Cloud API)</option>
          </select>
        </div>

        {/* Context Purpose */}
        <div className="form-group">
          <label htmlFor="purpose-select" className="form-label">
            <Tag size={13} style={{ display: 'inline', marginRight: '4px' }} aria-hidden="true" />
            Workflow Purpose
          </label>
          <select
            id="purpose-select"
            className="form-select"
            value={context.purpose}
            onChange={handlePurposeChange}
            disabled={disabled}
          >
            <option value="general_question">General Question</option>
            <option value="summarization">Summarization</option>
            <option value="coding">Coding / Technical</option>
            <option value="hr_workflow">HR Workflow</option>
            <option value="health_information">Health Information</option>
            <option value="other">Other</option>
          </select>
        </div>

        {/* Data Subject */}
        <div className="form-group">
          <label htmlFor="subject-select" className="form-label">
            <UserCheck size={13} style={{ display: 'inline', marginRight: '4px' }} aria-hidden="true" />
            Data Subject
          </label>
          <select
            id="subject-select"
            className="form-select"
            value={context.data_subject}
            onChange={handleDataSubjectChange}
            disabled={disabled}
          >
            <option value="none">None (General / Impersonal)</option>
            <option value="self">Self (User's Own Data)</option>
            <option value="third_party">Third Party (Customer / Partner)</option>
            <option value="employee">Employee (Internal Staff)</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>

        {/* Data Classification */}
        <div className="form-group">
          <label htmlFor="classification-select" className="form-label">
            <Shield size={13} style={{ display: 'inline', marginRight: '4px' }} aria-hidden="true" />
            Classification
          </label>
          <select
            id="classification-select"
            className="form-select"
            value={context.classification}
            onChange={handleClassificationChange}
            disabled={disabled}
          >
            <option value="public">Public</option>
            <option value="internal">Internal Only</option>
            <option value="confidential">Confidential</option>
            <option value="restricted">Restricted / Regulated</option>
          </select>
        </div>
      </div>
    </div>
  )
}
