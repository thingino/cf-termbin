// Headers that make a stored blob inert in a browser. text/plain plus nosniff is
// what actually stops a paste being rendered as HTML; the CSP and sandbox are
// belt and braces. Deliberately no Content-Disposition: attachment, because
// maintainers open these links from GitHub issues and forcing a download for
// every click would break the only way anyone reads them.
function inertHeaders() {
	return {
		'content-type': 'text/plain; charset=utf-8',
		'x-content-type-options': 'nosniff',
		'content-security-policy': "default-src 'none'; sandbox",
		'referrer-policy': 'no-referrer',
		// Search indexing is what would give a public diag bin value to a phisher
		// and discoverability to anyone trawling for device details.
		'x-robots-tag': 'noindex, nofollow, noarchive',
		// Nothing is cached at the edge. Reads are a few hundred a day so caching
		// buys nothing, and a cached copy would outlive both the delete token and
		// the read-time expiry check.
		'cache-control': 'no-store',
	};
}

export function textResponse(status, body, extra = {}) {
	return new Response(body, { status, headers: { ...inertHeaders(), ...extra } });
}

export function jsonResponse(status, obj) {
	return new Response(JSON.stringify(obj, null, 2) + '\n', {
		status,
		headers: { ...inertHeaders(), 'content-type': 'application/json; charset=utf-8' },
	});
}

export function pasteResponse(body, exp, extra = {}) {
	return new Response(body, {
		headers: {
			...inertHeaders(),
			'x-thingino-expires': new Date(exp * 1000).toISOString(),
			...extra,
		},
	});
}

// Missing, malformed and wrong-token all land here so that none of them confirms
// whether a slug exists. Expiry is the one case we do distinguish, with a 410.
export function notFound() {
	return textResponse(404, 'not found\n');
}
