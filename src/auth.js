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
// The builder's D1 is bound read-only in practice: nothing here writes to it. The one
// consequence is that `last_active` is not slid, so a session used only against this bin
// idles out on the builder's 2 hour window rather than being kept alive by activity
// here. That is a fair price for not being able to damage a live service's tables.
async function builderSession(request, env) {
	const token = bearer(request);
	if (!token) return null;

	const now = Math.floor(Date.now() / 1000);
	const row = await env.AUTHDB.prepare('SELECT admin, expires, last_active FROM sessions WHERE token = ?')
		.bind(await sha256hex(token))
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
