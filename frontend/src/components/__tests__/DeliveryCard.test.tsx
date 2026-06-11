import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import React from 'react'
import DeliveryCard from '../DeliveryCard'
import type { SmugResponse } from '../../api/smuggler'

const noop = vi.fn<[string], Promise<SmugResponse>>().mockResolvedValue({
  link_id: 'deadbeef00000000deadbeef00000000',
  url:     '/d/deadbeef00000000deadbeef00000000/loader.pdf',
})

const defaultProps = {
  artifactName: 'loader_abc123.exe',
  stageHost:    'c2.example.com',
  downloadId:   null,
  onSmuggle:    noop,
}

describe('DeliveryCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('renders Delivery heading', () => {
    render(React.createElement(DeliveryCard, defaultProps))
    expect(screen.getByText('Delivery')).toBeInTheDocument()
  })

  it('renders extension picker buttons', () => {
    render(React.createElement(DeliveryCard, defaultProps))
    expect(screen.getByRole('button', { name: '.pdf' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '.exe' })).toBeInTheDocument()
  })

  it('disables Smuggle button when downloadId is null', () => {
    render(React.createElement(DeliveryCard, defaultProps))
    expect(screen.getByRole('button', { name: /smuggle/i })).toBeDisabled()
  })

  it('enables Smuggle button when downloadId is provided', () => {
    render(React.createElement(DeliveryCard, { ...defaultProps, downloadId: 'abc-123' }))
    expect(screen.getByRole('button', { name: /smuggle/i })).not.toBeDisabled()
  })

  it('calls onSmuggle with fakeName when Smuggle clicked', async () => {
    const onSmuggle = vi.fn().mockResolvedValue({
      link_id: 'deadbeef00000000deadbeef00000000',
      url:     '/d/deadbeef00000000deadbeef00000000/loader_abc123.pdf',
    })
    render(React.createElement(DeliveryCard, { ...defaultProps, downloadId: 'abc-123', onSmuggle }))
    fireEvent.click(screen.getByRole('button', { name: /smuggle/i }))
    expect(onSmuggle).toHaveBeenCalledWith('loader_abc123.pdf')
  })

  it('shows Open and Copy link buttons after successful smuggle', async () => {
    const onSmuggle = vi.fn().mockResolvedValue({
      link_id: 'deadbeef00000000deadbeef00000000',
      url:     '/d/deadbeef00000000deadbeef00000000/loader.pdf',
    })
    render(React.createElement(DeliveryCard, { ...defaultProps, downloadId: 'abc-123', onSmuggle }))
    fireEvent.click(screen.getByRole('button', { name: /smuggle/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: /open/i })).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /copy link/i })).toBeInTheDocument()
  })

  it('does not show Send to Discord when defcrow_discord_url is absent', async () => {
    const onSmuggle = vi.fn().mockResolvedValue({
      link_id: 'deadbeef00000000deadbeef00000000',
      url:     '/d/deadbeef00000000deadbeef00000000/loader.pdf',
    })
    render(React.createElement(DeliveryCard, { ...defaultProps, downloadId: 'abc-123', onSmuggle }))
    fireEvent.click(screen.getByRole('button', { name: /smuggle/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: /open/i })).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /discord/i })).toBeNull()
  })

  it('shows Send to Discord when defcrow_discord_url is set', async () => {
    localStorage.setItem('defcrow_discord_url', 'https://discord.com/api/webhooks/123/abc')
    const onSmuggle = vi.fn().mockResolvedValue({
      link_id: 'deadbeef00000000deadbeef00000000',
      url:     '/d/deadbeef00000000deadbeef00000000/loader.pdf',
    })
    render(React.createElement(DeliveryCard, { ...defaultProps, downloadId: 'abc-123', onSmuggle }))
    fireEvent.click(screen.getByRole('button', { name: /smuggle/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: /send to discord/i })).toBeInTheDocument())
  })
})
