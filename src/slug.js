// Crockford base32 alphabet: no i, l, o or u, so slugs survive being read aloud
// off a terminal and pasted into an issue by hand.
const ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';
const TOKEN_LEN = 26; // 130 bits, delete capability

// Slug length is sized by hit density, not raw keyspace: what matters is how many
// guesses land on *any* live report, and only a few hundred exist at once under a
// 3 day retention. At 8 characters (40 bits) that is ~3.7e9 guesses against ~300
// live reports, and the free tier caps an enumerator at 100k requests/day, so
// about a century at the maximum possible rate. Seven is ~3 years, six is ~36 days.
export const DEFAULT_SLUG_LEN = 8;

// Validation accepts a range rather than one exact length, so changing the
// generated length later does not 404 every URL already pasted into an issue.
const SLUG_MIN = 4;
const SLUG_MAX = 26;
const SLUG_RE = new RegExp(`^[${ALPHABET}]{${SLUG_MIN},${SLUG_MAX}}$`);

// 256 is an exact multiple of 32, so masking a uniform byte stays uniform.
function randomChars(n) {
	const bytes = new Uint8Array(n);
	crypto.getRandomValues(bytes);
	let out = '';
	for (const b of bytes) out += ALPHABET[b & 31];
	return out;
}

export function newSlug(len = DEFAULT_SLUG_LEN) {
	const n = Number(len);
	const clamped = Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), SLUG_MIN), SLUG_MAX) : DEFAULT_SLUG_LEN;
	return randomChars(clamped);
}

export function newToken() {
	return randomChars(TOKEN_LEN);
}

// Cheap enough to run before touching the database, which keeps enumeration attempts
// from costing a query each.
export function isSlug(s) {
	return typeof s === 'string' && SLUG_RE.test(s);
}
