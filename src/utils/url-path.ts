/**
 * Guards for caller-supplied values that end up in Jamf request paths.
 *
 * Tool arguments are interpolated into URLs like
 * `/api/v2/local-admin-password/${id}/accounts`. Unencoded, an id containing
 * `/`, `..`, `?` or `#` changes which endpoint the backend's credential hits
 * (e.g. `<id>/account/<user>/password#` turns an accounts listing into a
 * password read). Every interpolated value goes through `pathSegment`, and the
 * request interceptor re-checks the final URL with `assertSafeRequestPath` so a
 * call site that forgets the helper still fails closed.
 */

/** Encode one value as exactly one path segment. Rejects empty and dot segments. */
export function pathSegment(value: string | number): string {
  const raw = String(value);
  if (raw === '' || raw === '.' || raw === '..') {
    throw new Error('Invalid identifier in request path');
  }
  return encodeURIComponent(raw);
}

/**
 * Reject a request URL whose path could have been re-routed by its inputs.
 * Query strings go through axios `params`, never inline, so `?` and `#` are
 * never legitimate here; neither are backslashes or dot segments (raw or
 * percent-encoded).
 */
export function assertSafeRequestPath(url: string | undefined): void {
  if (!url) return;
  const path = /^https?:\/\//i.test(url) ? url.replace(/^https?:\/\/[^/]*/i, '') : url;
  if (/[?#\\]/.test(path)) {
    throw new Error('Unsafe characters in request path');
  }
  for (const segment of path.split('/')) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new Error('Malformed request path');
    }
    if (decoded === '.' || decoded === '..') {
      throw new Error('Dot segment in request path');
    }
  }
}
