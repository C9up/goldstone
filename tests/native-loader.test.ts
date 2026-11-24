/**
 * Where the engine comes from: the local build of a checkout first, then the
 * platform package `@c9up/goldstone-<suffix>` an install brings in as an optional
 * dependency. A refusal names what to install, and keeps the load error, which
 * carries host paths, as its cause rather than in its message.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * The host the loader is told it runs on. Stubbed like `require` is, so the
 * suite asserts the same thing on every platform.
 */
const HOST = { platform: "linux", arch: "x64", suffix: "linux-x64-gnu" };

/** The platform package this host installs. */
const PLATFORM_PACKAGE = `@c9up/goldstone-${HOST.suffix}`;

/** A binary answering every call the package makes. */
const standIn = () =>
	new Proxy(
		{},
		{
			get: () => () => undefined,
		},
	);

/** What `require` throws for a module that is not there. */
function notFound(id: string): Error {
	return Object.assign(new Error(`Cannot find module '${id}'`), {
		code: "MODULE_NOT_FOUND",
	});
}

/** Load the engine module with `require` running `load` for every module it asks for. */
async function withRequire(
	load: (id: string) => unknown,
	host: { platform: string; arch: string } = HOST,
) {
	vi.resetModules();
	vi.doMock("node:process", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:process")>()),
		platform: host.platform,
		arch: host.arch,
	}));
	vi.doMock("node:module", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:module")>()),
		createRequire: () => load,
	}));
	return {
		native: await import("../src/native.js"),
		errors: await import("../src/errors.js"),
	};
}

/** What the first engine call throws, or `undefined` when it does not. */
function refusalOf(native: Awaited<ReturnType<typeof withRequire>>["native"]) {
	try {
		native.engine();
		return undefined;
	} catch (error) {
		return error;
	}
}

afterEach(() => {
	vi.doUnmock("node:process");
	vi.doUnmock("node:module");
	vi.resetModules();
});

describe("goldstone > the engine comes from the local build or the platform package", () => {
	it("loads the platform package when no local binary is built", async () => {
		const asked: string[] = [];
		const { native } = await withRequire((id) => {
			asked.push(id);
			if (id === PLATFORM_PACKAGE) return standIn();
			throw notFound(id);
		});

		expect(native.isNativeAvailable()).toBe(true);
		expect(asked).toHaveLength(2);
		expect(asked[0]).toMatch(/[\\/]index\.linux-x64-gnu\.node$/);
		expect(asked[1]).toBe(PLATFORM_PACKAGE);
	});

	it("prefers the local build, and never asks for the package then", async () => {
		const asked: string[] = [];
		const { native } = await withRequire((id) => {
			asked.push(id);
			return standIn();
		});

		expect(native.isNativeAvailable()).toBe(true);
		expect(asked).toHaveLength(1);
		expect(asked[0]).toMatch(/index\.linux-x64-gnu\.node$/);
	});

	it("names the platform package to install when neither is there", async () => {
		const { native, errors } = await withRequire((id) => {
			throw notFound(id);
		});

		const refusal = refusalOf(native);

		expect(native.isNativeAvailable()).toBe(false);
		expect(refusal).toBeInstanceOf(errors.E_GOLDSTONE_NATIVE_REQUIRED);
		expect(String(refusal)).toContain(
			`Fix: install ${PLATFORM_PACKAGE} at the exact version of @c9up/goldstone`,
		);
		expect(String(refusal)).toContain("pnpm build:napi");
		// The load error travels as the cause, not in the message.
		expect(refusal).toMatchObject({ cause: { code: "MODULE_NOT_FOUND" } });
		expect(String(refusal)).not.toContain("Cannot find module");
	});

	it("reports a local build that fails to load, instead of falling back to the package", async () => {
		const asked: string[] = [];
		const { native } = await withRequire((id) => {
			asked.push(id);
			throw new Error("invalid ELF header");
		});

		const refusal = refusalOf(native);

		expect(asked).toHaveLength(1);
		expect(String(refusal)).toContain(
			"Fix: index.linux-x64-gnu.node failed to load. Rebuild it: cd packages/goldstone && pnpm build:napi",
		);
		expect(String(refusal)).not.toContain("invalid ELF header");
		expect(refusal).toMatchObject({ cause: { message: "invalid ELF header" } });
	});

	it("lists the supported targets on a host no binary is built for", async () => {
		const asked: string[] = [];
		const { native } = await withRequire(
			(id) => {
				asked.push(id);
				return standIn();
			},
			{ platform: "linux", arch: "riscv64" },
		);

		const refusal = refusalOf(native);

		expect(asked).toHaveLength(0);
		expect(String(refusal)).toContain(
			"Fix: no prebuilt binary for linux-riscv64; goldstone ships one for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64.",
		);
	});
});
