import { describe, expect, it } from 'vitest'
import { parseECHKeypair } from './ech'

describe('ECH generation payload', () => {
  const config = ['-----BEGIN ECH CONFIGS-----', 'AAEA', '-----END ECH CONFIGS-----']
  const key = ['-----BEGIN ECH KEYS-----', 'AQID', '-----END ECH KEYS-----']

  it('accepts a complete base64 pair without changing the payload', () => {
    const lines = [...config, ...key]
    expect(parseECHKeypair(lines)).toEqual({ config, key })
    expect(lines).toEqual([...config, ...key])
  })

  it.each([
    null, [], ['Failed to generate ECH keypair: ', 'failure'], config,
    [...config, ...key.slice(0, -1)],
    [...config, ...key, ...key],
    [...config, '-----BEGIN ECH KEYS-----', 'not base64', '-----END ECH KEYS-----'],
    ['-----BEGIN ECH CONFIGS-----', 'AQID', '-----END ECH CONFIGS-----', ...key],
  ].map(value => ({ value })))('rejects incomplete/error responses before any model is changed: $value', ({ value }) => {
    expect(parseECHKeypair(value)).toBeUndefined()
  })
})
