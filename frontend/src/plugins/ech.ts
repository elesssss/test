// Validate both blocks before the form mutates either half of its TLS model.
export function parseECHKeypair(value: unknown): { config: string[], key: string[] } | undefined {
  if (!Array.isArray(value) || !value.every(line => typeof line === 'string')) return
  const lines = value.map(line => line.trim())
  const block = (name: string): string[] | undefined => {
    const begin = `-----BEGIN ECH ${name}-----`
    const end = `-----END ECH ${name}-----`
    const start = lines.indexOf(begin)
    const finish = lines.indexOf(end)
    if (start < 0 || finish <= start + 1 || lines.lastIndexOf(begin) !== start || lines.lastIndexOf(end) !== finish) return
    const body = lines.slice(start + 1, finish)
    const base64 = body.join('')
    if (!body.every(line => /^[A-Za-z0-9+/]+={0,2}$/.test(line))) return
    try {
      const decoded = atob(base64)
      if (decoded.length === 0 || btoa(decoded) !== base64) return
    } catch { return }
    return lines.slice(start, finish + 1)
  }
  const config = block('CONFIGS')
  const key = block('KEYS')
  if (!config || !key) return
  const bytes = atob(config.slice(1, -1).join(''))
  if (bytes.length < 3 || ((bytes.charCodeAt(0) << 8) | bytes.charCodeAt(1)) !== bytes.length - 2) return
  return { config, key }
}
