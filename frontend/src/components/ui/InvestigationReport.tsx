'use client'

import React, { Fragment, type ReactNode } from 'react'
import ReactMarkdown from 'react-markdown'

interface InvestigationReportProps {
  content: string
  answerType?: string
  confidence?: number
}

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
            if (className) {
              return (
                <pre className="ir-code-block">
                  <code className={className}>{children}</code>
                </pre>
              )
            }
            return <code className="ir-inline-code">{children}</code>
          },
          hr: () => <hr className="ir-divider" />,
          a: ({ href, children }) => {
            const safeHref = href && /^(https?:|\/|#|mailto:)/i.test(href.trim()) ? href : '#'
            const isExternal = safeHref.startsWith('http')
            return (
              <a
                href={safeHref}
                target={isExternal ? '_blank' : undefined}
                rel={isExternal ? 'noopener noreferrer' : undefined}
                className="text-[#10b981] underline hover:text-[#34d399]"
              >
                {children}
              </a>
            )
          },
          img: ({ alt }) => (
            <span className="inline-block rounded bg-[#f3f4f6] px-2 py-1 text-xs text-[#667085] font-mono">
              [{alt ? String(alt) : 'Image'} (external media blocked)]
            </span>
          ),
        }}
        urlTransform={(url: string) => {
          const trimmed = url.trim().toLowerCase()
          if (/^(https?:|\/|#|mailto:)/.test(trimmed)) {
            return url
          }
          return ''
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
