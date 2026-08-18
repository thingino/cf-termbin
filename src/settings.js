// How long a report is kept, set by an admin at runtime rather than at deploy.
//
// Two independent windows, because the two kinds are not alike: a diagnostic report is the thing
// this bin exists for and someone may need a few days to look at it, while a paste is casual and
// its shorter leash is what stops the permissive door being the expensive one.
//
// Read on every submission, so it is cached per isolate for a few seconds. That staleness is
// harmless: the worst case is one report stored under the previous window moments after it
// changed, and nothing already stored is affected either way.

// Deliberately a closed set rather than a free number. It keeps the storage arithmetic to four
// cases per kind that an admin can be shown, instead of an open field where 90 looks as
// reasonable as 3 and silently blows the database ceiling.
export const TTL_CHOICES = [1, 3, 5, 7];

// Empty means "nothing stored", so the deploy-time TTL_DAYS / PASTE_TTL_DAYS still decide. Giving
// these real numbers instead made the stored value always present, which shadowed the env vars
// entirely and quietly disabled the suite's TTL_DAYS=-1 expiry hook.
export const DEFAULTS = { ttl_diag: '', ttl_paste: '' };

const CACHE_MS = 5000;
let cached = null;
let cachedAt = 0;

export async function readSettings(env, { fresh = false } = {}) {
	const now = Date.now();
	if (!fresh && cached && now - cachedAt < CACHE_MS) return cached;

	const got = { ...DEFAULTS };
	try {
		const rows = await env.DB.prepare('SELECT key, value FROM settings').all();
		for (const r of rows.results || []) if (r.key in got) got[r.key] = r.value ?? '';
	} catch (err) {
		// A database that predates this table still serves reports; it just uses the defaults.
		console.log(`settings unavailable, using defaults: ${err}`);
	}
	cached = got;
	cachedAt = now;
	return got;
}

export async function writeSettings(env, patch) {
	const stmts = [];
	for (const [k, v] of Object.entries(patch)) {
		if (!(k in DEFAULTS)) continue;
		stmts.push(
			env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?').bind(
				k,
				String(v),
				String(v),
			),
		);
	}
	if (stmts.length) await env.DB.batch(stmts);
	cached = null; // so the next read is the value just written, not the one it replaced
}

// The stored value, the deploy-time default, and MAX_TTL_DAYS as a backstop, in that order. The
// cap is what keeps a settings row from outliving what the configuration intends.
export function ttlFor(kind, settings, env, num) {
	const stored = Number(kind === 'diag' ? settings.ttl_diag : settings.ttl_paste);
	const fallback = kind === 'diag' ? num(env.TTL_DAYS, 3) : num(env.PASTE_TTL_DAYS, 1);
	const chosen = TTL_CHOICES.includes(stored) ? stored : fallback;
	// No floor. A stored value is already one of TTL_CHOICES, so the only way to get a
	// non-positive number here is a deploy-time TTL_DAYS, which the suite sets negative on purpose
	// to make a report that is already expired. Clamping that away silently disabled the whole
	// expiry and reclaim section.
	return Math.min(chosen, num(env.MAX_TTL_DAYS, 7));
}
