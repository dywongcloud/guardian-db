// GuardianDB Edge Functions — Deno guest harness.
//
// Run as: deno run <perm flags> functions_deno_harness.ts <path-to-user-function>
// Stdin:  one JSON-encoded request envelope (see `functions_deno.rs::Envelope`,
//         which mirrors `functions::InvocationInput`'s wire shape).
// Stdout: exactly one JSON value — either the response envelope
//         `{status, headers, body_b64}` or a typed error
//         `{__gdb_error_kind: "boot" | "runtime", message}`.
//
// `console.*` is redirected to stderr before the user module is imported, so
// stdout stays reserved for that single JSON value regardless of what the
// deployed function logs. The parent process forwards stderr lines into
// GuardianDB's tracing — the `gdb.log` equivalent for this runtime.

function realStderr(s: string) {
  Deno.stderr.writeSync(new TextEncoder().encode(s + "\n"));
}

for (const method of ["log", "info", "warn", "error", "debug"] as const) {
  // deno-lint-ignore no-explicit-any
  (console as any)[method] = (...args: unknown[]) => {
    realStderr(`[console.${method}] ${args.map(String).join(" ")}`);
  };
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  if (b64.length === 0) return new Uint8Array(0);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Write the single result value and let `main` return normally. */
function writeResult(obj: unknown) {
  Deno.stdout.writeSync(new TextEncoder().encode(JSON.stringify(obj)));
}

type Envelope = {
  method: string;
  url: string;
  headers: [string, string][];
  body_b64: string;
};

type Handler = (req: Request) => Response | Promise<Response>;

let capturedHandler: Handler | undefined;

// Intercept `Deno.serve` so the module's top-level call registers a handler
// instead of actually binding a port — the invocation itself supplies one
// request and wants one response back, not a listening server.
// deno-lint-ignore no-explicit-any
(Deno as any).serve = (optsOrHandler: unknown, maybeHandler?: unknown) => {
  if (typeof optsOrHandler === "function") {
    capturedHandler = optsOrHandler as Handler;
  } else if (typeof maybeHandler === "function") {
    capturedHandler = maybeHandler as Handler;
  } else if (
    optsOrHandler &&
    typeof (optsOrHandler as { fetch?: unknown }).fetch === "function"
  ) {
    capturedHandler = (optsOrHandler as { fetch: Handler }).fetch;
  }
  return {
    finished: Promise.resolve(),
    shutdown: async () => {},
    ref: () => {},
    unref: () => {},
    addr: { transport: "tcp", hostname: "127.0.0.1", port: 0 },
  };
};

async function main() {
  const userPath = Deno.args[0];
  if (!userPath) {
    writeResult({ __gdb_error_kind: "boot", message: "no function path given" });
    return;
  }

  let mod: Record<string, unknown>;
  try {
    mod = await import(`file://${userPath}`);
  } catch (e) {
    writeResult({
      __gdb_error_kind: "boot",
      message: `failed to load function module: ${
        e instanceof Error ? e.message : String(e)
      }`,
    });
    return;
  }

  const handler = capturedHandler ??
    (typeof mod.default === "function" ? (mod.default as Handler) : undefined);
  if (!handler) {
    writeResult({
      __gdb_error_kind: "boot",
      message:
        "no request handler found: call Deno.serve(handler) or `export default` a handler function",
    });
    return;
  }

  let envelope: Envelope;
  try {
    const stdinBytes = await new Response(Deno.stdin.readable).arrayBuffer();
    envelope = JSON.parse(new TextDecoder().decode(stdinBytes));
  } catch (e) {
    writeResult({
      __gdb_error_kind: "runtime",
      message: `invalid input envelope: ${
        e instanceof Error ? e.message : String(e)
      }`,
    });
    return;
  }

  const method = envelope.method.toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD" &&
    envelope.body_b64.length > 0;

  let request: Request;
  try {
    request = new Request(envelope.url, {
      method,
      headers: envelope.headers,
      body: hasBody
        ? (base64ToBytes(envelope.body_b64) as BodyInit)
        : undefined,
    });
  } catch (e) {
    writeResult({
      __gdb_error_kind: "runtime",
      message: `failed to construct Request: ${
        e instanceof Error ? e.message : String(e)
      }`,
    });
    return;
  }

  let response: Response;
  try {
    const result = await handler(request);
    if (!(result instanceof Response)) {
      writeResult({
        __gdb_error_kind: "runtime",
        message: `handler must return a Response, got ${
          Object.prototype.toString.call(result)
        }`,
      });
      return;
    }
    response = result;
  } catch (e) {
    writeResult({
      __gdb_error_kind: "runtime",
      message: `handler threw: ${
        e instanceof Error ? `${e.name}: ${e.message}` : String(e)
      }`,
    });
    return;
  }

  try {
    const bodyBytes = new Uint8Array(await response.arrayBuffer());
    writeResult({
      status: response.status,
      headers: [...response.headers.entries()],
      body_b64: bytesToBase64(bodyBytes),
    });
  } catch (e) {
    writeResult({
      __gdb_error_kind: "runtime",
      message: `failed to serialize response: ${
        e instanceof Error ? e.message : String(e)
      }`,
    });
  }
}

await main();
