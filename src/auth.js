// Admin authentication, in three modes, so the bin is usable by someone who has no
// thingino image builder to log in against.
//
//   builder  Delegate to thingino-image-builder. An account there is an account here.
//   token    One ADMIN_KEY secret. What a self-hosted deployment wants.
//   none     No admin at all. The bin still accepts, serves and expires reports, and
//            submitters can still delete their own with the token they were given.
//
// The mode is inferred unless AUTH_MODE says otherwise, so neither deployment needs to
// set it: an AUTHDB binding means builder, an ADMIN_KEY secret means token, neither
// means none. Being explicit is supported and clearer for anything unattended.

import { sha256hex, constantTimeEqual } from './crypto.js';

const IDLE_SECS = 2 * 3600; // must match SESSION_IDLE_SECS in the builder

export function authMode(env) {
	const declared = (env.AUTH_MODE || '').trim().toLowerCase();
	if (declared === 'builder' || declared === 'token' || declared === 'none') return declared;
	if (env.AUTHDB) return 'builder';
	if (env.ADMIN_KEY) return 'token';
	return 'none';
}

function bearer(request) {
	const header = request.headers.get('authorization') || '';
	return header.startsWith('Bearer ') ? header.slice(7) : '';
}

// Delegated to thingino-image-builder, which already does this properly: PBKDF2-SHA256
// at 100k iterations, TOTP with a single-use step check, per-IP login throttling, and
// sessions stored as a hex SHA-256 so a database read cannot replay one. Reimplementing
// it would be worse in every way, and one way in particular: a local implementation
// would need TOTP_ENC_KEY copied into this Worker to unseal seeds, so compromising the
// newer, smaller service would hand over the builder's second factor. This Worker never
// sees a password or a seed.
//
// One statement in this Worker writes to the builder's database, and it is the slide at the
// end of this function. Everything else only reads. The rule it relaxes was never a security
// boundary, because a D1 binding is read-write at the platform level: it was blast-radius
// control against our own bugs touching a live service's tables. So the write is kept to a
// single UPDATE of one column on one row, reached only after every check below has passed.
//
// Without it, `last_active` stayed at whatever the builder set at login, so a session used
// only against this bin died a fixed 2 hours after login however hard it was being used,
// rather than 2 hours after going idle.
async function builderSession(request, env) {
	const token = bearer(request);
	if (!token) return null;

	const now = Math.floor(Date.now() / 1000);
	const hash = await sha256hex(token);
	const row = await env.AUTHDB.prepare('SELECT admin, expires, last_active FROM sessions WHERE token = ?')
		.bind(hash)
		.first();

	// Fail closed on every field. An empty `admin` must not stand in for the master
	// identity, which the builder sets explicitly.
	if (!row || !row.admin) return null;
	if (!(row.expires > now)) return null;
	if (!(row.last_active > now - IDLE_SECS)) return null;

	// Revocation is authoritative: a named admin's session is only good while the account
	// still exists and is enabled. Master is secret-based in the builder, with no row.
	if (row.admin !== 'master') {
		const account = await env.AUTHDB.prepare('SELECT disabled FROM admins WHERE username = ?')
			.bind(row.admin)
			.first();
		if (!account || account.disabled) return null;
	}

	// Slide the idle window, throttled to once a minute exactly as the builder throttles its
	// own. Deliberately last: an expired, idle or revoked session has already returned above,
	// so this can only extend a session that was valid on its own terms, and it never touches
	// `expires`, so the builder's 8 hour ceiling from login still bounds the whole thing.
	if (now - row.last_active >= 60) {
		try {
			await env.AUTHDB.prepare('UPDATE sessions SET last_active = ? WHERE token = ?').bind(now, hash).run();
		} catch (err) {
			// A session that could not be slid still works until its window runs out, so a failure
			// here must not fail the request it was serving.
			console.log(`session not slid: ${err}`);
		}
	}

	return row.admin;
}

// Returns the admin identity, or null. Callers treat null as "not found" rather than
// "forbidden", so a bad credential cannot be used to probe which admin paths exist.
export async function adminIdentity(request, env) {
	switch (authMode(env)) {
		case 'builder':
			return env.AUTHDB ? builderSession(request, env) : null;
		case 'token':
			// A single shared secret. Weaker than the builder's 2FA and deliberately so:
			// it is for a deployment with one operator and no identity provider to point
			// at. Constant-time compared, and it is the only credential, so rotating it
			// logs everyone out.
			return env.ADMIN_KEY && constantTimeEqual(bearer(request), env.ADMIN_KEY) ? 'admin' : null;
		default:
			return null;
	}
}
