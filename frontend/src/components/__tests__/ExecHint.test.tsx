import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import React from 'react'
import ExecHint from '../ExecHint'

describe('ExecHint', () => {
  it('shows wscript command for WSF', () => {
    render(React.createElement(ExecHint, { type: 'Wsf' }))
    expect(screen.getByText(/wscript\.exe loader\.wsf/)).toBeInTheDocument()
  })

  it('shows Squiblydoo signer for SCT', () => {
    render(React.createElement(ExecHint, { type: 'Regsvr32Sct' }))
    expect(screen.getByText(/Squiblydoo/)).toBeInTheDocument()
  })

  it('shows copy-paste warning for DocxMacro', () => {
    render(React.createElement(ExecHint, { type: 'DocxMacro' }))
    expect(screen.getByText(/copy-paste/i)).toBeInTheDocument()
  })

  it('shows command for all 14 loader types', () => {
    const all: any[] = [
      'Binary', 'Dll', 'AppDomain', 'Injector', 'Rundll32',
      'Wsf', 'Hta', 'Regsvr32Sct', 'MsBuild', 'Cmstp', 'WmicXsl',
      'DocxMacro', 'XlsxMacro', 'InstallUtil',
    ]
    all.forEach((t) => {
      const { unmount } = render(React.createElement(ExecHint, { type: t }))
      expect(screen.getByTestId('exec-hint')).toBeInTheDocument()
      unmount()
    })
  })
})
