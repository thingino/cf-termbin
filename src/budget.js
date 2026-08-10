import { DurableObject } from 'cloudflare:workers';

// A single global counter, not per-IP buckets.
//
// Per-IP fairness would be meaningless here: legitimate submitters are one-shot
// one-shot devices behind arbitrary NATs, so there is no repeat client to be fair to.
//
// It counts bytes as well as reports, per kind, and the byte budget is the one that
// matters. A free D1 database caps at 500 MB, and reports run around 430 KiB, so
// steady-state storage is bytes-per-day times the retention window. Bounding
// bytes bounds the database provably, without having to query its size:
// 100 MB/day at 3 day retention settles at 300 MB. A count-only limit could not
// do that, since 2000 reports at 1 MB would be 6 GB.
//
// One key, rewritten in place, so storage never grows. SQLite backend, which is
// the only Durable Object backend available on the Workers free plan.
export class DailyBudget extends DurableObject {
	// Counters are per kind, so the permissive client-token door cannot spend the
	// diag allowance. Called immediately before the write it protects, so rejected
	// submissions cost nothing.
	async take(day, kind, maxCount, maxBytes, size) {
		// The kill switch lives here rather than in a var, because a var needs a deploy and this
		// has to be reachable from the portal. It is checked before anything is counted, so a
		// paused bin does not spend budget, and it costs no extra round trip: submit already
		// calls this object.
		if (await this.ctx.storage.get('paused')) return { ok: false, reason: 'paused' };

		const state = (await this.ctx.storage.get('counter')) || { day: '', kinds: {} };

		// `|| !state.kinds` is load-bearing, not defensive padding. Durable Object
		// state outlives a deploy: an earlier version stored { day, n, bytes } with no
		// `kinds` at all, and on the day of the upgrade `state.day === day` is already
		// true, so a day-change-only reset leaves `kinds` undefined and the next line
		// throws. Local suites cannot catch this because they always start from a fresh
		// persist directory, which is exactly why it reached production.
		if (state.day !== day || !state.kinds) {
			state.day = day;
			state.kinds = {};
		}

		const k = state.kinds[kind] || { n: 0, bytes: 0 };

		if (k.n >= maxCount) return { ok: false, reason: `${kind} count`, ...k };
		if (k.bytes + size > maxBytes) return { ok: false, reason: `${kind} byte budget`, ...k };

		k.n += 1;
		k.bytes += size;
		state.kinds[kind] = k;
		await this.ctx.storage.put('counter', state);
		return { ok: true, ...k };
	}

	async peek() {
		const state = (await this.ctx.storage.get('counter')) || { day: '', kinds: {} };
		return { ...state, paused: Boolean(await this.ctx.storage.get('paused')) };
	}

	// Stored as its own key, not inside `counter`, so the daily reset cannot clear it: a bin
	// paused during an incident must stay paused across midnight.
	async setPaused(paused) {
		if (paused) await this.ctx.storage.put('paused', true);
		else await this.ctx.storage.delete('paused');
		return { paused: Boolean(paused) };
	}
}
