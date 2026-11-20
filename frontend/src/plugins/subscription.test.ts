import { describe, expect, it } from 'vitest'
import { happSubscriptionURL, subscriptionURL } from './subscription'

describe('subscription format URLs', () => {
  it('adds and replaces a format without dropping tokens or fragments', () => {
    const url = new URL(subscriptionURL('https://example.test/sub/alice?token=a%2Bb&format=json#profile', 'happ'))
    expect(url.searchParams.get('token')).toBe('a+b')
    expect(url.searchParams.getAll('format')).toEqual(['happ'])
    expect(url.hash).toBe('#profile')
  })

  it('uses the direct Happ add route with an explicit backend format', () => {
    expect(happSubscriptionURL('https://example.test/sub/alice')).toBe('happ://add/https://example.test/sub/alice?format=happ')
  })
})
