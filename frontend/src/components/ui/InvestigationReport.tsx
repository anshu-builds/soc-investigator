'use client'

import React, { Fragment, type ReactNode } from 'react'
import ReactMarkdown from 'react-markdown'

interface InvestigationReportProps {
  content: string
  answerType?: string
  confidence?: number
}

/**
 * Replace [EV-NNN] tokens in a text string with styled evidence chips.
 * Returns a ReactNode array with chip spans interspersed with plain text.
 */
function renderWithEvidence(children: ReactNode): ReactNode {
  if (typeof children === 'string') {
    const parts = children.split(/(\[EV-\d{3,}\])/g)
    if (parts.length === 1) return children
    return (
      <>
        {parts.map((part, i) =>
          /^\[EV-\d{3,}\]$/.test(part) ? (
            <span key={i} className="evidence-chip">{part}</span>
          ) : (
            <Fragment key={i}>{part}</Fragment>
          )
        )}
      </>
    )
  }
  if (Array.isArray(children)) {
    return children.map((child, i) => (
      <Fragment key={i}>{renderWithEvidence(child)}</Fragment>
    ))
  }
  return children
}

/** Normalize heading text to a canonical section label */
function getSectionLabel(children: ReactNode): string | null {
  let text = ''
  if (typeof children === 'string') {
    text = children
  } else if (Array.isArray(children)) {
    text = children
      .map((c) => (typeof c === 'string' ? c : ''))
      .join('')
  }
  const lower = text.toLowerCase().trim()
  const LABELS: Record<string, string> = {
    summary: 'SUMMARY',
    timeline: 'TIMELINE',
    evidence: 'EVIDENCE',
    assessment: 'ASSESSMENT',
    'mitre att&ck': 'MITRE ATT&CK',
    'mitre attack': 'MITRE ATT&CK',
    'recommended actions': 'RECOMMENDED ACTIONS',
    recommendations: 'RECOMMENDED ACTIONS',
    confidence: 'CONFIDENCE',
  }
  return LABELS[lower] ?? null
}

/**
 * InvestigationReport renders an AI investigation response as a structured,
 * readable SOC report using react-markdown with custom component renderers.
 *
 * Markdown is parsed correctly: headings, bold, lists, code, paragraphs.
 * Evidence references [EV-NNN] are rendered as styled chips.
 */
export function InvestigationReport({
  content,
  answerType,
  confidence,
}: InvestigationReportProps) {
  return (
    <div className="investigation-report">
      <ReactMarkdown
        components={{
          h1: ({ children }) => (
            <h2 className="ir-section-heading">
              {getSectionLabel(children) ?? children}
            </h2>
          ),
          h2: ({ children }) => (
            <h2 className="ir-section-heading">
              {getSectionLabel(children) ?? children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="ir-section-heading ir-section-heading--sub">
              {getSectionLabel(children) ?? children}
            </h3>
          ),
          p: ({ children }) => (
            <p className="ir-paragraph">{renderWithEvidence(children)}</p>
          ),
          ul: ({ children }) => <ul className="ir-list">{children}</ul>,
          ol: ({ children }) => <ol className="ir-list-ordered">{children}</ol>,
          li: ({ children }) => (
            <li className="ir-list-item">{renderWithEvidence(children)}</li>
          ),
          strong: ({ children }) => (
            <strong className="ir-strong">{renderWithEvidence(children)}</strong>
          ),
          em: ({ children }) => <em>{renderWithEvidence(children)}</em>,
          code: ({ children, className }) => {
            // Fenced code block (has language className)
            if (className) {
              return (
                <pre className="ir-code-block">
                  <code className={className}>{children}</code>
                </pre>
              )
            }
            // Inline code
            return <code className="ir-inline-code">{children}</code>
          },
          hr: () => <hr className="ir-divider" />,
        }}
      >
        {content}
      </ReactMarkdown>

      {(answerType || confidence !== undefined) && (
        <div className="ir-footer">
          {answerType && (
            <span className="ir-footer-type">
              {answerType.replace('_', ' ').toLowerCase()}
            </span>
          )}
          {confidence !== undefined && (
            <span className="ir-footer-confidence">
              {Math.round(confidence * 100)}% confidence
            </span>
          )}
        </div>
      )}
    </div>
  )
}
