// Browser tests for the admin page, which tests/smoke.sh cannot reach: it exercises the
// Worker, and the page's own logic is where a credential can be sent to the wrong place.
//
// Driven by tests/web.sh, which starts a static server standing in for GitHub Pages and a
// Worker that proxies it at /admin/. UI is therefore the WORKER origin: the page and the API
// share it, exactly as in production. Run directly with UI=<origin> MODE=<token|builder>.
//
// Two things a first attempt at this got wrong, both of which made it pass against
// known-broken code. They are why the harness looks like it does:
//
//   1. web/admin.js captures AUTH into a module-scope const at load, so assigning
//      window.AUTH_ORIGIN afterwards changes nothing and the request goes wherever the
//      committed config.js pointed. config.js is intercepted instead.
//   2. The page's real CSP allows 'self' plus one named builder origin, so a POST to a
//      recorder on another localhost port is blocked before it is made and never arrives.
//      AUTH_ORIGIN is therefore the page's own origin, which 'self' allows, and the
//      builder endpoints are captured by the route handler rather than by a server. In
//      production the target is the named builder origin the CSP allows, so this is not
//      working around a block that would save anyone.

const UI = (process.env.UI || '').replace(/\/+$/, '');
const MODE = process.env.MODE || 'token';
const KEY = process.env.ADMIN_KEY || 'self-hosted-key';
const SESSION = process.env.SESSION || 'localsession';
// Wide enough that the signin race is deterministic rather than a coin flip.
const MODE_DELAY_MS = Number(process.env.MODE_DELAY_MS || 2500);

let pass = 0;
let fail = 0;
const ok = (name, cond, detail = '') => {
	if (cond) {
		pass++;
		console.log(`  ok   ${name}`);
	} else {
		fail++;
		console.log(`  FAIL ${name}${detail ? `\n       ${detail}` : ''}`);
	}
};

// Playwright is not a dependency of this project: it pulls a browser download, and the
// Worker tests must stay installable without one. Resolve it if it happens to be around
// and skip loudly if not, rather than failing a suite for a missing optional tool.
async function loadChromium() {
	const candidates = [process.env.PLAYWRIGHT_PATH, 'playwright'].filter(Boolean);
	const { globSync } = await import('node:fs');
	for (const c of globSync(`${process.env.HOME}/.npm/_npx/*/node_modules/playwright/index.mjs`)) {
		candidates.push(c);
	}
	for (const c of candidates) {
		try {
			return (await import(c)).chromium;
		} catch {
			/* try the next */
		}
	}
	return null;
}

const chromium = await loadChromium();
if (!chromium) {
	console.log('  SKIP playwright not resolvable; set PLAYWRIGHT_PATH to its index.mjs');
	process.exit(0);
}
if (!UI) {
	console.log('  FAIL UI is not set; run tests/web.sh instead');
	process.exit(1);
}

const browser = await chromium.launch();

// One page run. Returns what the builder endpoints saw, which in token mode must be
// nothing at all.
async function run({ modeDelay, fill, act }) {
	const builderHits = [];
	const offsite = [];
	const errors = [];

	const ctx = await browser.newContext();
	await ctx.route('**/*', async (route) => {
		const req = route.request();
		const u = new URL(req.url());

		if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') {
			offsite.push(`${req.method()} ${req.url()}`);
			return route.abort();
		}
		if (u.pathname.startsWith('/api/admin/')) {
			builderHits.push({
				path: u.pathname,
				auth: req.headers()['authorization'] || '',
				body: req.postData() || '',
			});
			return route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ session: SESSION }),
			});
		}
		if (u.pathname.endsWith('/config.js')) {
			return route.fulfill({
				status: 200,
				contentType: 'application/javascript',
				body: `window.API_BASE="";window.AUTH_ORIGIN="${UI}";window.APP_VERSION="0.0.0";window.GIT_SHA="test";`,
			});
		}
		if (u.pathname === '/admin/mode' && modeDelay) {
			await new Promise((r) => setTimeout(r, modeDelay));
		}
		return route.continue();
	});

	const page = await ctx.newPage();
	page.on('pageerror', (e) => errors.push(String(e)));
	// Through the Worker's /admin/ proxy, so the test exercises the production path.
	await page.goto(`${UI}/admin/`, { waitUntil: 'domcontentloaded' });
	await page.waitForSelector('#p');

	await fill(page);
	await page.click('#signin');
	await page
		.waitForFunction(() => document.querySelector('#app').style.display !== 'none', { timeout: 20000 })
		.catch(() => {});

	const signedIn = await page.evaluate(() => document.querySelector('#app').style.display !== 'none');
	const gateErr = await page.evaluate(() => (document.querySelector('#gateErr') || {}).textContent || '');
	const hitsAtSignin = builderHits.length;

	// enter() fires refresh() without awaiting it, so wait for the timestamp it sets last.
	let rows = 0;
	let listErr = '';
	let actResult;
	if (signedIn) {
		await page
			.waitForFunction(() => (document.querySelector('#updated').textContent || '').length > 0, { timeout: 20000 })
			.catch(() => {});
		({ rows, listErr } = await page.evaluate(() => {
			const t = document.querySelector('#reports tbody');
			return { rows: t ? t.rows.length : 0, listErr: (document.querySelector('#err') || {}).textContent || '' };
		}));
		if (act) actResult = await act(page);
	}

	await ctx.close();
	return { signedIn, gateErr, rows, listErr, builderHits, hitsAtSignin, offsite, errors, actResult };
}

const leaks = (hits, secret) => hits.filter((h) => h.auth.includes(secret) || h.body.includes(secret));

// Does the master toggle actually swap which credential the gate asks for?
async function masterFieldsHidden() {
	const ctx = await browser.newContext();
	await ctx.route('**/config.js', (route) =>
		route.fulfill({
			status: 200,
			contentType: 'application/javascript',
			body: `window.API_BASE="";window.AUTH_ORIGIN="${UI}";window.APP_VERSION="0.0.0";window.GIT_SHA="test";`,
		}),
	);
	const page = await ctx.newPage();
	await page.goto(`${UI}/admin/`, { waitUntil: 'networkidle' });
	await page.click('#masterToggle');
	const state = await page.evaluate(() => ({
		u: document.querySelector('#u').hidden,
		p: document.querySelector('#p').hidden,
		mt: document.querySelector('#mt').hidden,
		t: document.querySelector('#t').hidden,
	}));
	await ctx.close();
	return state.u && state.p && !state.mt && !state.t;
}

if (MODE === 'token') {
	console.log('-- token mode: the admin key is the bin\'s own and must never leave it');

	// Submitted inside the delayed /admin/mode window, which is the race that used to send
	// the key to AUTH_ORIGIN as a password.
	const raced = await run({
		modeDelay: MODE_DELAY_MS,
		fill: (p) => p.fill('#p', KEY),
		act: (p) => p.click('#lock').then(() => p.waitForTimeout(1500)),
	});
	ok('signs in with the admin key while /admin/mode is still in flight', raced.signedIn, raced.gateErr);
	ok('the report list loads', raced.rows > 0 && !raced.listErr, `rows=${raced.rows} err=${raced.listErr}`);
	ok(
		'no builder endpoint is called at all',
		raced.builderHits.length === 0,
		raced.builderHits.map((h) => `${h.path} auth=${h.auth} body=${h.body}`).join('; '),
	);
	ok(
		'the admin key never reaches AUTH_ORIGIN',
		leaks(raced.builderHits, KEY).length === 0,
		JSON.stringify(leaks(raced.builderHits, KEY)),
	);
	ok('nothing offsite is attempted', raced.offsite.length === 0, raced.offsite.join('; '));
	ok('no page errors', raced.errors.length === 0, raced.errors.join('; '));

	// And with the mode already settled, which isolates sign-out: that path needed no race.
	const settled = await run({
		modeDelay: 0,
		fill: (p) => p.fill('#p', KEY),
		act: (p) => p.click('#lock').then(() => p.waitForTimeout(1500)),
	});
	ok('signs in with the mode already settled', settled.signedIn, settled.gateErr);
	ok(
		'signing out does not post the key to AUTH_ORIGIN',
		settled.builderHits.length === 0,
		settled.builderHits.map((h) => `${h.path} auth=${h.auth}`).join('; '),
	);
	// Retention is set here rather than at deploy, so the page is where it can go wrong: a
	// select that posts the other kind's value, or a saved value that does not survive a reload.
	const ttl = await run({
		modeDelay: 0,
		fill: (p) => p.fill('#p', KEY),
		act: async (p) => {
			await p.waitForSelector('#ttlDiag option', { state: 'attached', timeout: 20000 });
			const before = await p.locator('#ttlPaste').inputValue();
			await p.selectOption('#ttlDiag', '7');
			const noted = await p.locator('#ttlNote').textContent();
			await p.click('#saveTtl');
			await p.waitForFunction(() => document.querySelector('#ttlMsg').textContent === 'saved', { timeout: 20000 });
			// Reload rather than trust the page: the value has to have reached the database.
			await p.reload({ waitUntil: 'domcontentloaded' });
			await p.waitForFunction(() => document.querySelector('#ttlDiag').value !== '', { timeout: 20000 });
			const after = {
				diag: await p.locator('#ttlDiag').inputValue(),
				paste: await p.locator('#ttlPaste').inputValue(),
				noted,
			};
			// Put it back, so a suite run leaves no setting behind.
			await p.selectOption('#ttlDiag', '3');
			await p.click('#saveTtl');
			await p.waitForFunction(() => document.querySelector('#ttlMsg').textContent === 'saved', { timeout: 20000 });
			return { before, after, restored: await p.locator('#ttlDiag').inputValue() };
		},
	});
	const t = ttl.actResult || {};
	ok('a retention window survives a reload', t.after?.diag === '7', JSON.stringify(t.after));
	ok('and the other kind is left alone', t.after?.paste === t.before, `${t.before} -> ${t.after?.paste}`);
	ok(
		'the storage arithmetic follows the select, not the saved value',
		(t.after?.noted || '').includes('× 7'),
		t.after?.noted,
	);
	ok('it can be set back', t.restored === '3', String(t.restored));
} else {
	console.log('-- builder mode: login and revocation both belong to the builder');

	const r = await run({
		modeDelay: 0,
		fill: async (p) => {
			await p.fill('#u', 'local');
			await p.fill('#p', 'whatever');
			await p.fill('#t', '000000');
		},
		act: (p) => p.click('#lock').then(() => p.waitForTimeout(1500)),
	});
	ok('signs in through the builder', r.signedIn, r.gateErr);
	// Proves the page is talking to a real Worker that accepted the seeded session, not
	// just flipping a div.
	ok('the seeded session is accepted by the bin', r.rows > 0 && !r.listErr, `rows=${r.rows} err=${r.listErr}`);

	const login = r.builderHits.filter((h) => h.path === '/api/admin/login');
	const logout = r.builderHits.filter((h) => h.path === '/api/admin/logout');
	ok('credentials go to the builder, not the bin', login.length === 1, JSON.stringify(login));
	ok('the password never reaches the bin', login.every((h) => h.body.includes('whatever')), JSON.stringify(login));
	ok('the second factor is sent with it', login.every((h) => JSON.parse(h.body).totp === '000000'), JSON.stringify(login));
	ok('signing out revokes at the builder', logout.length === 1, JSON.stringify(logout));
	ok(
		'revocation carries the session',
		logout.length === 1 && logout[0].auth === `Bearer ${SESSION}`,
		JSON.stringify(logout),
	);
	ok('no page errors', r.errors.length === 0, r.errors.join('; '));

	// Master token: the builder's own alternative to username and password, and the same
	// endpoint. What matters is that it is still a two-factor exchange rather than a way past
	// one, so the body must carry the code and must not carry a username or password.
	const m = await run({
		modeDelay: 0,
		fill: async (p) => {
			await p.click('#masterToggle');
			await p.fill('#mt', 'master-token-value');
			await p.fill('#t', '000000');
		},
	});
	ok('master token signs in', m.signedIn, m.gateErr);
	const mlogin = m.builderHits.filter((h) => h.path === '/api/admin/login');
	ok('it goes to the builder', mlogin.length === 1, JSON.stringify(mlogin));
	if (mlogin.length === 1) {
		const b = JSON.parse(mlogin[0].body);
		ok('as a token plus the code', b.token === 'master-token-value' && b.totp === '000000', mlogin[0].body);
		ok('and never as a username or password', b.username === undefined && b.password === undefined, mlogin[0].body);
	}
	ok('the toggle hides username and password', await masterFieldsHidden(), 'fields still visible');
}

await browser.close();
console.log(`\npassed: ${pass}   failed: ${fail}`);
process.exit(fail === 0 ? 0 : 1);
