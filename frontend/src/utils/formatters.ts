/**
 * OWASP Sentinel - Date & Time Formatting Utilities
 *
 * Ensures accurate UTC-to-local timezone conversion, seconds precision,
 * and intuitive relative time displays (e.g. "Just now", "4m ago").
 */

export function parseUtcDate(isoString: string | undefined | null): Date | null {
  if (!isoString) return null;
  // If string has no timezone indicator, append Z to ensure UTC interpretation
  const hasTimezone = isoString.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(isoString);
  const normalized = hasTimezone ? isoString : `${isoString}Z`;
  const parsed = new Date(normalized);
  return isNaN(parsed.getTime()) ? null : parsed;
}

export function formatExactDateTime(isoString: string | undefined | null): string {
  const date = parseUtcDate(isoString);
  if (!date) return 'N/A';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  });
}

export function formatDateTimeShort(isoString: string | undefined | null): string {
  const date = parseUtcDate(isoString);
  if (!date) return 'N/A';
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
  });
}

export function formatRelativeTime(isoString: string | undefined | null): string {
  const date = parseUtcDate(isoString);
  if (!date) return 'Unknown';

  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 10) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;

  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;

  const diffDay = Math.floor(diffHr / 24);
  if (diffDay === 1) return 'Yesterday';
  if (diffDay < 30) return `${diffDay}d ago`;

  const diffMonth = Math.floor(diffDay / 30);
  if (diffMonth === 1) return '1mo ago';
  if (diffMonth < 12) return `${diffMonth}mo ago`;

  const diffYear = Math.floor(diffDay / 365);
  return `${diffYear}y ago`;
}

/**
 * Strips any legacy 'Kali Practice Script(s):' prefix and script filenames from titles,
 * ensuring users see strictly the vulnerability/bug name only.
 */
export function cleanBugTitle(title: string | undefined | null): string {
  if (!title) return '';
  return title
    .replace(/^Kali Practice Scripts?:\s*/i, '')
    .replace(/\s*\([^)]*\.py[^)]*\)$/i, '')
    .trim();
}

/**
 * Accurately extracts the specific vulnerable endpoint URL where an issue was found,
 * rather than only returning the root canonical URL.
 *
 * Checks:
 * 1. Specific vulnerable URLs with pathnames/query params (e.g. https://target.com/wp-login.php)
 * 2. Evidence fields: portal_path, path, endpoint_path, relative_url combined with base origin
 * 3. Title patterns like "Publicly Exposed Administrative Login Portal (/wp-login.php)"
 * 4. Fallback to candidate URLs and canonical asset origin
 */
export function getVulnerableEndpointUrl(finding?: any | null, asset?: any | null): string {
  if (!finding) return '';
  const ev = finding.evidence || {};
  const rawProof = ev.practical_proof || {};

  // Base origin fallback candidates
  const baseCandidates = [
    asset?.canonical_url,
    ev.target_url,
    ev.canonical_url,
    rawProof.target_endpoint,
    asset?.host ? `${asset.scheme || 'https'}://${asset.host}/` : null,
  ];

  let baseOrigin = '';
  for (const b of baseCandidates) {
    if (typeof b === 'string' && b.trim().startsWith('http') && !b.includes('//target')) {
      baseOrigin = b.trim();
      break;
    }
  }
  if (!baseOrigin) {
    baseOrigin = asset?.host ? `https://${asset.host}/` : 'https://target/';
  }

  // 1. Check candidate URLs that already possess a specific subpath or query
  const directUrlCandidates = [
    ev.vulnerable_url,
    ev.url,
    ev.affected_url,
    ev.endpoint,
    ev.probe_url,
    ev.test_url,
    rawProof.vulnerable_url,
    rawProof.target_endpoint,
  ];

  for (const u of directUrlCandidates) {
    if (typeof u === 'string' && u.trim().startsWith('http') && !u.includes('//target')) {
      try {
        const parsed = new URL(u.trim());
        // Specific endpoint has a pathname other than root '/' or has query parameters
        if ((parsed.pathname && parsed.pathname !== '/') || parsed.search) {
          return u.trim();
        }
      } catch {}
    }
  }

  // 2. Relative subpaths from evidence: portal_path, path, endpoint_path, etc.
  const pathCandidates = [
    ev.portal_path,
    ev.path,
    ev.endpoint_path,
    ev.relative_path,
    ev.relative_url,
    ev.page_path,
  ];

  for (const p of pathCandidates) {
    if (typeof p === 'string' && p.trim()) {
      try {
        return new URL(p.trim(), baseOrigin).href;
      } catch {}
    }
  }

  // 3. Check finding.title for embedded path e.g. "(/wp-login.php)" or "(/admin)"
  const title = finding.title || '';
  const titlePathMatch = title.match(/\((\/[a-zA-Z0-9_\-\.\/]+)\)/);
  if (titlePathMatch && titlePathMatch[1]) {
    try {
      return new URL(titlePathMatch[1], baseOrigin).href;
    } catch {}
  }

  // 4. If any candidate URL is a valid http string, return it even if root
  for (const u of directUrlCandidates) {
    if (typeof u === 'string' && u.trim().startsWith('http') && !u.includes('//target')) {
      return u.trim();
    }
  }

  return baseOrigin;
}


