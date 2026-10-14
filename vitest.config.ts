import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		coverage: {
			provider: "v8",
			include: ["src/**"],
			// `src/vendor/**` is generated from scripts/vendor/ and identical in every
			// package that carries it; the generated native surface is the Rust's.
			exclude: ["src/**/*.d.ts", "src/native/generated.ts", "src/vendor/**"],
			reporter: ["text-summary", "json-summary"],
			// A floor, not a target: set just under what the suite covers today.
			// Branches sit lower because the loader's "binary missing" and "binary
			// failed to load" paths cannot run where the binary loads.
			// Measured with the IMAP test server up (GOLDSTONE_IMAP_TEST_PORT), as CI
			// runs it: without one, the IMAP suites skip and this floor fails.
			thresholds: {
				lines: 96,
				statements: 93,
				branches: 76,
				functions: 88,
			},
		},
	},
});
