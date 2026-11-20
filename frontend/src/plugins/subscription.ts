// Keep existing query parameters and URL fragments when selecting a format.
export function subscriptionURL(value: string, format: 'json' | 'clash' | 'happ'): string {
  const url = new URL(value, window.location.href)
  url.searchParams.set('format', format)
  return url.toString()
}

export function happSubscriptionURL(value: string): string {
  // Happ's add/ route takes the subscription URL directly, not URL-encoded.
  return 'happ://add/' + subscriptionURL(value, 'happ')
}
