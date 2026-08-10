// Where the UI points. API_BASE is empty because the Worker serves this page from /admin/
// on its own origin, so every API call is same-origin. AUTH_ORIGIN is the one genuinely
// cross-origin dependency: credentials go straight to the builder and never touch the bin.
// The Pages workflow rewrites this file at deploy time.
window.API_BASE = "";
window.AUTH_ORIGIN = "https://thingino-image-builder-1d2e9b23.thingino.workers.dev";
window.APP_VERSION = "0.1.0";
window.GIT_SHA = "dev";
