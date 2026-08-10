// Shared by the delete-token check and by session lookup, which is why these live here
// rather than in either caller. They were duplicated in src/slug.js and src/auth.js, and
// two copies of a comparison whose whole purpose is not to leak timing is the kind of
// thing that drifts quietly.

export async function sha256hex(s) {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Length is compared first and therefore leaks, which is fine: both callers compare
// fixed-width values (a hex digest, or a configured key against itself).
export function constantTimeEqual(a, b) {
	if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}
