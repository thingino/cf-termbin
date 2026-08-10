// Two gates, and neither one hunts for secrets.
//
// Censoring is the diag script's job. It runs on the device, it is easy to change,
// and it is the only place a secret can be stopped before it leaves. A backend
// censor duplicates that logic badly, silently rewrites the maintainer's log, and
// creates a false impression that the bin is the safety net.
//
// What the bin defends is itself. It is a public write endpoint, and the service it
// replaces (fiche on a raw TCP port) was found storing command and control
// material for other people.
//
//   gate 1  FORMAT: is this a thingino diag report at all?
//   gate 2  SHAPE:  does it read like a log, or like a payload in a log's envelope?

// --- gate 1: format -------------------------------------------------------
//
// Fingerprints what the producing tool already emits, so no client change is needed and
// everything already deployed passes. This gate does the overwhelming majority of
// the work: the real artifact recovered from the old service was a 670 byte
// plaintext HTTP POST (an XXL-JOB /run RCE attempt carrying a `wget|sh` dropper),
// dumped in by an internet scanner that found the open netcat port. It has no
// ===[ THINGINO ]=== block, so it is refused outright.

const MARKER = '===[ THINGINO ]';
const ID_LINE = /^ID=thingino[\r]?$/m;
const HEADER_WINDOW = 8192;

export function parseEnvelope(text) {
	const head = text.slice(0, HEADER_WINDOW);

	// Two independent markers, so a log body that merely quotes our section header
	// does not get through on that alone.
	if (!head.includes(MARKER) || !ID_LINE.test(head)) {
		return { ok: false, error: 'not a thingino diag report (no ===[ THINGINO ]=== block with ID=thingino)' };
	}

	// Nothing is lifted out of the report at all. The gate answers one question.
	//
	// Two things used to be taken from here and are deliberately not. SOC, IMAGE_ID and
	// BUILD_ID went into three columns for the admin listing, which amounted to a hardware
	// inventory maintained by a paste bin. A `#redacted: <n>` line declared which censor
	// ruleset produced the report, checked against a MIN_REDACT_VERSION floor so firmware
	// predating a known censor gap could be refused; nothing ever emitted the line, so the
	// column held 24 zeroes and the floor was never raised. Both were cost without a reader.
	return { ok: true };
}

// --- gate 2: shape --------------------------------------------------------
//
// For the case gate 1 does not cover: someone who bothers to wrap a payload in a valid
// looking envelope. A diagnostic log and an embedded payload look nothing alike, and the
// difference is cheap to measure.
//
// Measured on real reports pulled off three devices, against the same 48 KiB payload
// embedded five ways:
//
//                            real reports   unwrapped   PEM 64   chunk 39   chunk 24   base32
//   encoded-token ratio          0.00%        93%         82%       50%        33%       64%
//   longest token             138 - 190     64,000        64        39         24        39
//   consecutive b64 lines           0            1      1,500         0         0         0
//   text bytes                 99.98%         100%       100%      100%      100%      100%
//
// The **ratio is the primary signal** and it is measured per whitespace-delimited token, not
// per run of base64 characters. Run length was the original rule and it was the wrong thing
// to key on, because it is the one thing an attacker sets for free: the chunk-39 column read
// 0.0% under it, while a `sha256sum` listing read 79% and was refused. Both directions wrong
// at once. The lengths are backstops for a payload small enough to hide inside the ratio.
//
// This is also why YARA and ClamAV were never the answer. A signature engine would not have
// flagged what was actually found, because a plaintext JSON exploit POST has no signature to
// match, and it would not flag an encrypted payload either. Shape does not care what the
// bytes decode to. The magic signatures below are a cheap addition to that, not a substitute:
// they catch a known container, and the ratio catches everything else.

// Sized off measured margins, and re-sized against real reports pulled off three lab
// devices (410 KiB/30 sections, 58 KiB/24, 52 KiB/23) plus a degraded run
// and a synthesised floor case. Each comment is the observed value, so the headroom is
// auditable rather than a guess.
export const SHAPE_DEFAULTS = {
	blobPercent: 10, // real 0.00 on every sample; a payload runs 32-100
	// A ratio alone cannot judge a small body: one API key or one ssh public key is most of a
	// 400 byte config, so the percentage is high while the absolute amount of encoded material
	// is trivial. Measured false positives that were nothing but this: a 996 byte footer.html
	// with a 29 character analytics key at 11.5%, and a 397 byte authorized_keys at 68.5%.
	// Below this floor the ratio is not consulted at all. A payload worth the trouble of
	// hiding here is orders of magnitude larger, and the small hostile cases have their own
	// checks: the artifact actually recovered was 670 bytes and was caught by its loader
	// chain, and a base64 shell script or ELF is caught by its magic regardless of size.
	minBlobBytes: 1024,
	// Real reports measure 138-190, always the NFS mount option string in MOUNT. The old 384
	// was 2x that and looked fine until the same mount was priced over IPv6: the kernel
	// prints the literal address into mountaddr= and addr=, taking that token to 242, and
	// NFSv4.2 over IPv6 to 308-365 depending on options. Nothing measured actually crossed
	// 384, so this is a margin argument, not a demonstrated failure: 19 characters of
	// headroom on an ordinary mount, on a network this project treats as the default, is not
	// margin. Raising it costs close to nothing, because the check only catches a blob left
	// unwrapped and the ratio already refuses those at 99.9%.
	maxToken: 1024,
	maxB64Lines: 8, // real 0 on every sample
	minPrintablePercent: 95, // real 99.976-99.998, now counting valid UTF-8 as text
	// A backstop for the one hole that counting UTF-8 as text opened: a payload re-encoded as
	// multi-byte sequences is text by the measure above, where before it read as binary.
	//
	// 95, not the 40 this started at, and the number is set by real text rather than by the
	// attack. Diag reports run 0.002-0.024% non-ASCII and an emoji-dense wifi scan on a small
	// report reaches 13.9%, which suggested plenty of room. Then the false-positive sweep found
	// 78 real text files above 40%, topping out at 88.2%: they are the Chinese translations of
	// the kernel documentation, shipped inside this very firmware tree. A log written in any
	// non-Latin script sits in the same range.
	//
	// So this check cannot be tight. Binary re-encoded as pure 2-byte sequences is 100% by
	// construction and is still refused, but anything that mixes in ASCII sits below 95 and gets
	// through, and no threshold separates CJK prose from UTF-8-wrapped bytes. It is kept because
	// closing the naive case costs nothing measurable, not because it is a real boundary. The
	// checks that do the work are the blob ratio for base64 and base32, the digest-length rule
	// for hex, and the printable ratio for raw bytes.
	maxNonAsciiPercent: 95,
	// See knownSections below: this is a floor against a bare envelope, not a fingerprint.
	minSections: 3,
	minKnownSections: 2,
};

// Section names seen across two versions of the producing tool, which is the point:
// the fleet does not agree on the set. `inforun` emits a header only when its command
// produced output, so a section vanishes when the tool is missing, the hardware lacks the
// feature or the daemon is dead. Measured spread: 30 names on a T31X, 24 on a T40N, 23 on
// a T21N (no wifi sections despite having wifi, because wpa_cli was not running), and 5 in
// the floor case where only the unconditional headers survive.
//
// So this is a generous union, not a required set, and the threshold is 2. A real report
// clears it by an order of magnitude; a payload in a hand-made `===[ THINGINO ]===`
// wrapper clears only THINGINO. New names in a future firmware cost nothing, since the
// test is a minimum.
const KNOWN_SECTIONS = new Set([
	'THINGINO', 'SOC', 'ENV', 'thingino.json', 'CMDLINE', 'GPIO', 'DF', 'IPC', 'MMC',
	'KMOD', 'KMOD-2', 'USB', 'MEMORY', 'MOUNT', 'OVERLAY', 'CLOCKS', 'isp-fs', 'isp-m0',
	'isp_info', 'libimp meminfo', 'libimp system_info', 'libimp fs_info', 'libimp enc_info',
	'sensor', 'PS', 'LSOF', 'NETWORK', 'ROUTE', 'WIFI-INFO', 'WPA-STATUS', 'WIFI-SCAN',
	'DMESG', 'LOGCAT', 'SYSLOG', 'streamer', 'RESOLV', 'WPA-CONF', 'crontab',
]);
const SECTION_NAME_MAX = 40; // longest known name is 18; this only bounds the inline read

// Character classes as a lookup table rather than comparison chains.
//
// This is not premature: the scan is pure CPU against a 10 ms budget, and the
// comparison-chain version measured 4.4 ms on a 427 KiB report, which extrapolates
// to ~13 ms at the 1 MB cap and would have been killed mid-request. One indexed
// read and three bit tests per character replaces about fifteen comparisons.
//
//   bit 0  printable ASCII (plus tab, CR, LF)
//   bit 1  whitespace
//   bit 2  base64 charset, A-Z a-z 0-9 + /
//   bit 3  UTF-8 continuation byte, 0x80-0xBF
//
// `=` is deliberately NOT in the base64 class even though it is valid padding.
// Including it made the `===[ SECTION ]======...` decoration count as blob: a small
// report measured 23.3% against a 25% limit purely from its own section headers, so
// a degraded device producing little output would have been refused. Padding is one
// or two characters at the end of a blob, so dropping it costs nothing.
const CLS = new Uint8Array(256);
for (let c = 0; c < 256; c++) {
	let f = 0;
	if ((c >= 0x20 && c <= 0x7e) || c === 9 || c === 10 || c === 13) f |= 1;
	if (c === 32 || c === 9 || c === 10 || c === 13) f |= 2;
	if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47) f |= 4;
	if (c >= 0x80 && c <= 0xbf) f |= 8;
	// bit 4: part of an encoded-data token. The base64 charset minus '/', because '/' and '='
	// are treated as token delimiters. See the accounting in measureShape for why.
	if ((f & 4) && c !== 47) f |= 16;
	CLS[c] = f;
}

const TOKEN_MIN = 24; // shorter than this is an identifier or a short field, not a payload

// Digest lengths in hex characters: crc32, md5, sha1, sha224, sha256, sha384, sha512.
// A pure-hex token of exactly one of these is a checksum, which `sha256sum` output is made
// of and which must not read as encoded data. Any other length of pure hex is hex-encoded
// something. Restricting it to exact lengths rather than "up to 128" is what stops a payload
// chunked into arbitrary hex widths from hiding behind the exclusion; a payload chunked to
// exactly 64 still can, and that is the one hole neither this nor the old rule closes.
const DIGEST_LENGTHS = new Set([8, 32, 40, 56, 64, 96, 128]);

// Two digits in a token of 24 or more. Base64 draws digits 10 times in 64 symbols and base32
// 6 in 32, so a real encoded token of this length almost always has several: at 24 characters
// the chance of fewer than two is about 9% for base64 and negligible for base32, and a
// payload is made of hundreds of tokens, so the ratio barely moves. A CamelCase identifier
// has none, which is the point. This came from a false positive: `mender.conf` measured 22.6%
// on `InventoryPollIntervalSeconds` and friends, uppercase plus lowercase and no digits.
const TOKEN_MIN_DIGITS = 2;

// Bytes to charge to the encoded-data total for one finished token, [from, to).
function classifyToken(bytes, from, to) {
	const len = to - from;
	let upper = 0;
	let lower = 0;
	let digits = 0;
	let hex = true;
	for (let i = from; i < to; i++) {
		const c = bytes[i];
		if (c >= 65 && c <= 90) {
			upper = 1;
			if (c > 70) hex = false;
		} else if (c >= 97 && c <= 122) {
			lower = 1;
			if (c > 102) hex = false;
		} else if (c >= 48 && c <= 57) {
			digits++;
		} else {
			hex = false; // '+' only; '=' and '/' are delimiters
		}
	}
	if (hex && DIGEST_LENGTHS.has(len)) return 0;
	if (digits < TOKEN_MIN_DIGITS) return 0;
	// Encoded data of this length mixes character classes; a path segment does not. Two of
	// three rather than all three, because all-uppercase base32 would otherwise be invisible:
	// measured 0% at three classes, 64.5% at two.
	return upper + lower + 1 >= 2 ? len : 0;
}

// How many continuation bytes a lead byte promises, or 0 if it is not a valid lead.
// 0xC0/0xC1 are overlong forms and 0xF5-0xFF are past the end of Unicode, so neither is
// ever valid and both are left at 0.
const UTF8_LEN = new Uint8Array(256);
for (let c = 0xc2; c <= 0xdf; c++) UTF8_LEN[c] = 1;
for (let c = 0xe0; c <= 0xef; c++) UTF8_LEN[c] = 2;
for (let c = 0xf0; c <= 0xf4; c++) UTF8_LEN[c] = 3;

// One pass computing every signal at once, over the RAW bytes rather than the
// decoded string.
//
// Both parts matter, and both were measured against the 10 ms CPU budget on a
// 427 KiB report. Separate regex sweeps would each traverse the whole body; and
// indexing a Uint8Array is about 36% cheaper than charCodeAt on a string, which at
// the size cap is the difference between fitting and being killed mid-request.
// Scanning the original bytes is also strictly more accurate for binary detection,
// since the decoded string has already replaced invalid sequences with U+FFFD.
//
// "Printable" means text, not ASCII. Counting only 0x20-0x7e made every valid UTF-8
// sequence read as binary, and real reports do carry some: the T31X sample has 31 em
// dashes plus a copyright and a micro sign, from program version banners. That is 0.024%
// and harmless, but WIFI-SCAN prints `wpa_cli scan_results` verbatim, and accented or
// emoji SSIDs are ordinary. Measured: 200 non-ASCII SSID rows on a small report took it to
// 94.1% and a `binary_content` refusal. Well-formed sequences are now counted as the text
// they are, and a uniformly random byte stream still measures ~45% printable against the
// 95% floor, because random bytes rarely form valid UTF-8.
export function measureShape(bytes) {
	const len = bytes.length;
	let printable = 0;
	let nonAscii = 0;
	let tokenRun = 0;
	let maxToken = 0;
	let b64Run = 0;
	let blobBytes = 0;
	let tokLen = 0;
	let lineLen = 0;
	let lineNonB64 = 0;
	let lineBlob = 0;
	let consecB64 = 0;
	let maxConsecB64 = 0;
	let sections = 0;
	let knownSections = 0;
	let atLineStart = true;
	// Bytes of a UTF-8 sequence still owed, and how many to credit once it completes.
	// Nothing is credited until it does, so a truncated or invalid sequence counts as the
	// non-text it is.
	let utf8Owed = 0;
	let utf8Width = 0;

	for (let i = 0; i < len; i++) {
		const c = bytes[i];
		const f = CLS[c];

		if (f & 1) {
			printable++;
			utf8Owed = 0; // ASCII cannot appear mid-sequence; abandon any partial one
		} else {
			if (c >= 0x80) nonAscii++;
			if (utf8Owed > 0 && f & 8) {
				// Mid-sequence and the byte is a continuation. Credit the whole sequence only
				// once it completes, so a truncated or malformed one counts as the non-text
				// it is.
				if (--utf8Owed === 0) printable += utf8Width;
			} else {
				// Either not in a sequence, or the one in flight just broke. Either way this
				// byte gets tested as a fresh lead; a broken sequence credits nothing.
				const w = UTF8_LEN[c];
				utf8Owed = w;
				utf8Width = w + 1;
			}
		}

		// '===[ ' at the start of a line.
		if (atLineStart && c === 61 && bytes[i + 1] === 61 && bytes[i + 2] === 61 && bytes[i + 3] === 91 && bytes[i + 4] === 32) {
			sections++;
			// Read the name inline rather than in a second regex sweep. Headers are rare
			// (30 in 410 KiB), so the cost is nothing next to another full traversal.
			let end = i + 5;
			const stop = Math.min(len, end + SECTION_NAME_MAX);
			while (end < stop && bytes[end] !== 93 && bytes[end] !== 10) end++;
			if (bytes[end] === 93) {
				let name = '';
				for (let j = i + 5; j < end; j++) name += String.fromCharCode(bytes[j]);
				if (KNOWN_SECTIONS.has(name.trim())) knownSections++;
			}
		}
		atLineStart = false;

		if (f & 2) {
			if (tokenRun > maxToken) maxToken = tokenRun;
			tokenRun = 0;
		} else {
			tokenRun++;
		}

		if (f & 4) {
			b64Run++;
		} else {
			b64Run = 0;
			if (c !== 10) lineNonB64++;
		}

		// Encoded-data accounting, per TOKEN rather than per run of base64 characters.
		//
		// Run length was the wrong thing to key on, because it is the one thing an attacker
		// sets for free. Measured: a 72 KiB base64 payload behind a fake kernel-log prefix
		// measured 64.9% at 40 characters per line and 0.0% at 39, because the old rule only
		// counted runs of 40 or more. The same rule refused `sha256sum` output at 79%. It was
		// wrong in both directions at once.
		//
		// Tokens break on whitespace and also on '=' and '/'. Both matter and both came from
		// measurement: without '=', `psk=<64 hex>` reads as one token and the digest exclusion
		// misses it; without '/', `find /sys/class` output measured 28.9%, because sysfs paths
		// are lowercase, digits and slashes, which is the same signature as base64.
		//
		// Only the LENGTH is tracked per byte. Classifying every byte as it went cost 5.5 ms at
		// the size cap and took the whole scan to 10.5 ms, past the request budget; a finished
		// token long enough to matter gets a second look instead. Real reports have almost no
		// tokens this long, so the second look is nearly free, and a body made of them is
		// getting refused anyway.
		if (f & 16) {
			tokLen++;
		} else {
			if (tokLen >= TOKEN_MIN) {
				const charged = classifyToken(bytes, i - tokLen, i);
				blobBytes += charged;
				lineBlob += charged;
			}
			tokLen = 0;
		}

		if (c === 10) {
			// `lineBlob > 0` is the difference between a PEM line and a line of slash-separated
			// path segments. Both are 40-plus characters drawn only from the base64 alphabet, so
			// the character test alone counted a listing of long sysfs paths as an encoded block.
			// Tokens break on '/', so a path line charges nothing and no longer counts.
			if (lineLen >= 40 && lineNonB64 === 0 && lineBlob > 0) {
				consecB64++;
				if (consecB64 > maxConsecB64) maxConsecB64 = consecB64;
			} else {
				consecB64 = 0;
			}
			lineLen = 0;
			lineNonB64 = 0;
			lineBlob = 0;
			atLineStart = true;
		} else {
			lineLen++;
		}
	}

	// The body may not end with a delimiter.
	if (tokLen >= TOKEN_MIN) blobBytes += classifyToken(bytes, len - tokLen, len);
	if (tokenRun > maxToken) maxToken = tokenRun;

	return {
		bytes: len,
		blobPercent: len ? (blobBytes / len) * 100 : 0,
		blobBytes,
		maxToken,
		maxB64Lines: maxConsecB64,
		printablePercent: len ? (printable / len) * 100 : 100,
		nonAsciiPercent: len ? (nonAscii / len) * 100 : 0,
		sections,
		knownSections,
	};
}

// Executable and archive magic, raw and base64.
//
// Which RAW magics are listed depends on whether they survive the lossy UTF-8 decode this
// runs against, and that is worth getting right rather than assuming:
//
//   \x7fELF     survives  (0x7f is valid ASCII, DEL)
//   PK\x03\x04  survives  (0x03 and 0x04 are valid ASCII)
//   \x1f\x8b    does NOT  (0x8b is an invalid continuation byte, becomes U+FFFD)
//
// So gzip appears in base64 form only. Raw gzip is caught by the printable ratio instead,
// which is the right tool for a binary stream anyway.
//
// The BASE64 signatures are generated rather than written out, because a literal only
// matches when the magic happens to land on a 3-byte boundary of the encoded stream. The old
// hand-written list (TVqQ, f0VMR, H4sI, UEsDB) was alignment 0 only, so prepending a single
// byte before encoding defeated all of it. Measured on a real ELF, gzip stream and zip
// archive: the old list caught 1 of 3 alignments, this catches 3 of 3.
//
// Magics are carried long enough that every alignment yields at least six characters, and
// ELF is enumerated over the class and endianness bytes that actually occur rather than
// truncated. 52 signatures, zero matches across 3.6 MiB of real firmware scripts and real
// device output.
// Split by alignment coverage, because coverage is not free. Every added alternative makes
// the regex slower, and not smoothly: 5 literals cost 0.27 ms over 768 KiB, 26 cost 0.34, and
// 52 cost 4.66, because a wider set of possible first characters defeats V8's prefilter. So
// the formats worth catching whatever the alignment get all three, and the rest get the
// classic alignment 0 only. 32 signatures, 1.18 ms.
const bytesOf = (s) => [...s].map((c) => c.charCodeAt(0));

// Four, not six. gzip has only four reliable header bytes (magic, method, flags) before a
// variable mtime, so its shifted alignments are four characters long, and dropping them is
// what let a 1-byte prefix hide a gzip stream. The old code already shipped a 4-character
// gzip literal, `H4sI`, so this is not a new risk: verified zero matches across 5.4 MiB of
// real firmware scripts, configs and device output.
const MAGIC_MIN_CHARS = 4;

// Deliberately the SHORTEST stable prefix of each magic, not the longest known header. An
// earlier version enumerated ELF over its class and endianness bytes, twelve bytes each, and
// produced twelve ELF signatures where three suffice: those bytes only affect characters
// after the part every ELF shares, so the short prefix covers strictly more files in a
// quarter of the alternatives. That matters because alternation count, not length, is what
// costs: 26 alternatives measure 0.34 ms over 768 KiB and 52 measure 4.66.
// The set is small on purpose, and choosing it was a cost exercise rather than a coverage
// one. Measured over 512 KiB of real log text: 12 signatures cost 0.78 ms, 21 cost 1.96 and
// 29 cost 2.47, against a 10 ms request budget that the byte pass already spends half of. So
// this covers exactly the four formats the old alignment-0-only list covered, at all three
// alignments, which is the 3x that actually mattered: a single prepended byte used to defeat
// every one of them.
//
// The millisecond figures throughout this file are local measurements. The edge is about 8x
// slower per unit work: `wrangler tail` reports 61 ms of cpuTime for a submission at the size
// cap, against 7.9 ms measured here, and it succeeds. Treat them as relative costs for
// comparing options, not as a distance to a 10 ms cliff.
//
// Deliberately NOT here, having been measured and dropped: xz, zstd, bzip2, 7z, rar, mach-o,
// java, upx, and the uClibc and musl interpreter paths. Together they cost another 1.7 ms and
// none of them is what an IoT payload store holds. If the budget grows, they are the first
// things to add back, and MAGIC_FIRST_ALIGNMENT is where they go.
const MAGIC_ALL_ALIGNMENTS = [
	[0x7f, 0x45, 0x4c, 0x46], // ELF, any class or endianness
	[0x4d, 0x5a, 0x90, 0x00], // PE
	[0x1f, 0x8b, 0x08, 0x00], // gzip; only FLG is reliable, the mtime that follows is not
	[0x50, 0x4b, 0x03, 0x04], // zip, jar, apk
	bytesOf('#!/bin/sh'), // a base64 shell script, the usual second stage
];

const MAGIC_FIRST_ALIGNMENT = [];

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function base64Of(bytes) {
	let out = '';
	for (let i = 0; i < bytes.length; i += 3) {
		const n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
		out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
	}
	return out;
}

const MAGIC_SIGNATURES = (() => {
	const seen = new Set();
	for (const [magic, alignments] of [
		...MAGIC_ALL_ALIGNMENTS.map((m) => [m, [0, 1, 2]]),
		...MAGIC_FIRST_ALIGNMENT.map((m) => [m, [0]]),
	]) {
		for (const pad of alignments) {
			// Keep only the characters determined solely by the magic, so the padding choice
			// cannot leak into the signature.
			const encoded = base64Of([...new Array(pad).fill(0x5a), ...magic]);
			const from = Math.ceil((pad * 8) / 6);
			const to = Math.floor(((pad + magic.length) * 8) / 6);
			const sig = encoded.slice(from, to);
			if (sig.length >= MAGIC_MIN_CHARS) seen.add(sig);
		}
	}
	return [...seen];
})();

const EXECUTABLE = new RegExp(
	['\\x7fELF', 'PK\\x03\\x04', ...MAGIC_SIGNATURES.map((s) => s.replace(/[+/]/g, '\\$&'))].join('|'),
);

// Fetch-and-run, which is the shape actually recovered from the old service. Bounded
// repetition throughout so a pathological line cannot make the scan expensive.
//
// The original covered only `wget|curl ... | sh`, which misses most of what IoT loaders
// actually do. Every pattern here was checked against 3.6 MiB of real content (962 firmware
// scripts including every init script, plus 49 real command outputs and five diag reports)
// and none of them fires on any of it.
// Each entry is [guard, pattern]. The guard is a plain literal alternation that the pattern
// cannot possibly match without, and it exists for cost: the eight patterns together measure
// 1.80 ms over 512 KiB, and a real report contains no fetch verb at all, so the guards skip
// almost all of that. Guarding on something too broad achieves nothing, which is worth
// stating because the obvious guard is exactly that: real reports do contain `busybox` and
// `http://`, so gating on those would never skip anything.
// Grouped under SHARED guards, not one guard each. Even a plain literal alternation costs
// 0.1 to 0.4 ms over 512 KiB, so eight guards cost more than the patterns they were meant to
// avoid: 1.55 ms of guard for patterns that a real report never reaches. Three groups instead.
const LOADERS = [
	[
		/wget|curl|tftp|ftpget/i,
		[
			// A fetch piped into any interpreter, including `| busybox sh`, which the original
			// missed and which is the Mirai-family default.
			/\b(?:wget|curl|tftp|ftpget)\b[^\n|]{0,200}\|\s*(?:\.\/|\/bin\/|busybox\s+)?(?:ba|a|da|k|z)?sh\b/i,
			/\b(?:wget|curl)\b[^\n|]{0,200}\|\s*(?:python[23]?|perl|lua|node)\b/i,
			// Fetch, make executable, run. No pipe, so the rule above cannot see it.
			/\b(?:wget|curl|tftp)\b[^\n;&]{0,200}[;&\n][^\n]{0,120}\bchmod\s+(?:[+ugoa]*x|[0-7]{3,4})\b/i,
		],
	],
	[
		// Decode-then-run, the usual second stage.
		/base64|atob|<\(/i,
		[
			/base64\s+(?:-d|--decode|-D)[^\n|]{0,80}\|\s*(?:\.\/|\/bin\/|busybox\s+)?(?:ba)?sh\b/i,
			/eval\s*\(\s*(?:atob|base64_decode)|\.\s*<\(\s*(?:curl|wget)/i,
		],
	],
	[
		// Family and platform markers, unambiguous when present.
		/MIRAI|ECCHI|LZRD|OWARI|APEP|SORA|powershell|FromBase64|ncodedCommand/i,
		[
			/\/bin\/busybox\s+(?:MIRAI|ECCHI|LZRD|OWARI|APEP|SORA)\b/,
			/-[Ee]ncoded[Cc]ommand|FromBase64String|powershell\s+-[Nn]op/,
		],
	],
	[
		// A per-architecture binary as the whole final path element, which is how a loader picks
		// its payload. Anchored at the end of the token: without that a legitimate mirror URL
		// ending in x86_64 matched, and one did in the kernel's ktest examples. Unguarded because
		// a real report does contain URLs and the word mips, and it measures 0.10 ms anyway.
		null,
		[/https?:\/\/[^\s"'`;|]{0,120}\/(?:mips|mpsl|arm[4-7]?|x86|i[356]86|sh4|ppc|spc|m68k|arc)(?=[\s"'`;|)]|$)/i],
	],
];

// Returns the failing check's name plus the measurements, or null.
//
// Only the name goes to the client. The numbers go to the Worker log, so a
// rejection does not hand an operator a dial to tune against.
export function scanShape(bytes, text, limits = {}) {
	const t = { ...SHAPE_DEFAULTS, ...limits };
	const metrics = measureShape(bytes);

	let failed = null;
	if (EXECUTABLE.test(text)) failed = 'executable_image';
	else if (
		t.blockDroppers !== false &&
		LOADERS.some(([guard, patterns]) => (!guard || guard.test(text)) && patterns.some((re) => re.test(text)))
	)
		failed = 'dropper_chain';
	else if (metrics.blobBytes >= t.minBlobBytes && metrics.blobPercent > t.blobPercent) failed = 'encoded_blob';
	else if (metrics.maxToken > t.maxToken) failed = 'oversized_token';
	else if (metrics.maxB64Lines > t.maxB64Lines) failed = 'encoded_block';
	else if (metrics.printablePercent < t.minPrintablePercent) failed = 'binary_content';
	else if (metrics.nonAsciiPercent > t.maxNonAsciiPercent) failed = 'encoded_text';
	// Both only apply to a recognised report, where the caller passes non-zero minimums.
	// The count is a floor against a bare wrapper; the named check is the one that means
	// anything, and it is the one a real report clears by an order of magnitude.
	else if (metrics.sections < t.minSections) failed = 'too_few_sections';
	else if (metrics.knownSections < (t.minKnownSections || 0)) failed = 'no_known_sections';

	return { failed, metrics };
}
