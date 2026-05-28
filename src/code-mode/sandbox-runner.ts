/**
 * Sandbox Runner — Executes agent-authored JavaScript in an isolated-vm
 * Isolate (a separate V8 instance with its own heap, no shared memory with
 * the host realm).
 *
 * Security model: node:vm is NOT a security boundary — its sandbox shares
 * builtins by reference with the host realm, so user code can reach `process`
 * via `Object.constructor → outer Function`. isolated-vm runs each sandbox
 * in a separate V8 isolate; values crossing the boundary are deep-copied
 * (via ExternalCopy semantics) by the Callback bridge below.
 *
 * All Jamf API calls are bridged into the host via the `_callJamfMethod`
 * Callback, which enforces capability checks, the BudgetTracker, plan/apply
 * mode, and approval-gated high-impact operations BEFORE invoking the real
 * client.
 */

import ivm from 'isolated-vm';
import * as crypto from 'node:crypto';
import { IJamfApiClient } from '../types/jamf-client.js';
import {
  ExecuteInput,
  ExecutionResult,
  LogEntry,
  ExecutionMode,
} from './types.js';
import {
  checkAccess,
  getClassification,
  BudgetTracker,
  requiresApproval,
  getAllMethodNames,
} from './policy-engine.js';
import { DiffBuilder } from './diff-builder.js';
import { ConcurrencyLimiter } from '../utils/throttle.js';

const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_MEMORY_MB = 128;
const sandboxThrottle = new ConcurrencyLimiter();

/** Pending approval tokens: token → list of blocked operations. */
const pendingApprovals = new Map<string, { method: string; args: unknown[] }[]>();

function getTimeout(): number {
  const env = process.env.JAMF_CODE_MODE_TIMEOUT;
  return env ? parseInt(env, 10) || DEFAULT_TIMEOUT : DEFAULT_TIMEOUT;
}

function getMemoryLimit(): number {
  const env = process.env.JAMF_CODE_MODE_MEMORY_MB;
  return env ? parseInt(env, 10) || DEFAULT_MEMORY_MB : DEFAULT_MEMORY_MB;
}

/**
 * Bootstrap that runs inside the isolate to expose `jamf`, `helpers`, and
 * `log/warn/error` to user code. `_callJamfMethod` is a Callback bound to the
 * host bridge below; isolated-vm auto-copies arguments and return values via
 * ExternalCopy when crossing the boundary.
 */
function buildBootstrap(methodNames: string[]): string {
  const names = JSON.stringify(methodNames);
  return `
    "use strict";
    const _METHODS = ${names};
    // Reference.apply options: arguments are deep-copied across the boundary
    // (going host-ward); the host's returned promise is awaited and its
    // resolved value is deep-copied back to the isolate. No host-realm
    // references leak in either direction.
    const _OPTS = {
      arguments: { copy: true },
      result: { promise: true, copy: true },
    };
    const jamf = {};
    for (const m of _METHODS) {
      jamf[m] = async (...args) => {
        // Host bridge returns {ok, value} | {ok:false, error}; we re-throw
        // in the isolate so user code can catch via standard try/catch.
        // (Direct host-promise rejection does NOT propagate across the
        // boundary — it surfaces as an unhandled rejection on the host.)
        const r = await _callJamfMethod.apply(undefined, [m, args], _OPTS);
        if (r && r.ok === false) throw new Error(r.error);
        return r ? r.value : undefined;
      };
    }
    const log = (...args) => _logMessage.applyIgnored(undefined, ['info', args], { arguments: { copy: true } });
    const warn = (...args) => _logMessage.applyIgnored(undefined, ['warn', args], { arguments: { copy: true } });
    const error = (...args) => _logMessage.applyIgnored(undefined, ['error', args], { arguments: { copy: true } });
    const console = { log, warn, error };
    const helpers = {
      paginate: async (fn, limit = 500) => fn(limit),
      daysSince(iso) {
        if (!iso) return Infinity;
        const ms = Date.now() - new Date(iso).getTime();
        return Math.floor(ms / 86400000);
      },
      chunk(arr, size) {
        const out = [];
        for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
        return out;
      },
    };
    globalThis.jamf = jamf;
    globalThis.helpers = helpers;
    globalThis.log = log;
    globalThis.warn = warn;
    globalThis.error = error;
    globalThis.console = console;
  `;
}

export async function execute(
  client: IJamfApiClient,
  input: ExecuteInput,
): Promise<ExecutionResult> {
  const { code, mode, capabilities, approval } = input;
  const logs: LogEntry[] = [];
  const diff = new DiffBuilder();
  const budget = new BudgetTracker();
  const start = Date.now();

  // Each invocation gets a fresh isolate. Memory bounded; the script.run()
  // timeout below bounds wall-clock CPU.
  const isolate = new ivm.Isolate({ memoryLimit: getMemoryLimit() });

  try {
    const context = await isolate.createContext();
    const jail = context.global;
    await jail.set('global', jail.derefInto());

    // Host-side bridge — every jamf method call from the isolate lands here.
    // All access control runs in the trusted host realm before we touch the
    // real client. Errors are returned as { ok: false, error } values rather
    // than thrown, because isolated-vm doesn't propagate host promise
    // rejections back into the isolate (they'd become unhandled rejections
    // on the host process). The bootstrap re-throws on the isolate side so
    // user code sees standard Error objects via try/catch.
    type Resp = { ok: true; value: unknown } | { ok: false; error: string };
    const callJamfMethod = async (name: string, argsCopy: unknown[]): Promise<Resp> => {
      try {
        const access = checkAccess(name, capabilities);
        if (!access.allowed) {
          return { ok: false, error: `Access denied: ${access.reason}` };
        }

        const budgetCheck = budget.trackCall(name);
        if (!budgetCheck.allowed) {
          return { ok: false, error: `Budget exceeded: ${budgetCheck.reason}` };
        }

        const classification = getClassification(name);
        if (!classification) {
          return { ok: false, error: `Unknown jamf method: ${name}` };
        }

        // Plan mode: block writes and commands.
        if (mode === 'plan' && classification !== 'read') {
          diff.record(classification, name, argsCopy);
          logs.push({
            level: 'info',
            msg: [`[plan] Blocked ${classification}: ${name}(${argsCopy.length} args)`],
          });
          return {
            ok: true,
            value: { blocked: true, method: name, args: argsCopy, classification },
          };
        }

        // Apply mode: gate high-impact methods behind approval token.
        if (mode === 'apply' && classification === 'command' && requiresApproval(name)) {
          if (!approval) {
            diff.record(classification, name, argsCopy);
            return {
              ok: true,
              value: { blocked: true, requiresApproval: true, method: name, args: argsCopy },
            };
          }
          if (!pendingApprovals.has(approval)) {
            return {
              ok: false,
              error: 'Invalid or expired approval token. Re-run with mode: "plan" to generate a new token.',
            };
          }
        }

        const method = (client as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>)[name];
        if (typeof method !== 'function') {
          return { ok: false, error: `Unknown jamf method: ${name}` };
        }
        const result = await sandboxThrottle.run(() => method.apply(client, argsCopy));
        diff.record(classification, name, argsCopy, result);
        return { ok: true, value: result };
      } catch (e) {
        // Real backend errors (HTTP failures, etc.) — return as values so
        // user code can catch them via standard try/catch in the isolate.
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    };

    // Host log sink (no return; safe to fire-and-forget).
    const logHost = (level: string, args: unknown[]): void => {
      logs.push({ level: level as 'info' | 'warn' | 'error', msg: args });
    };

    // Bridges are References — the isolate explicitly calls .apply with
    // copy options to traverse the boundary, giving us control over what
    // gets copied and when. (Callback auto-copies but its sync/async modes
    // didn't handle our host-async-fn-returning-objects pattern cleanly.)
    await jail.set('_callJamfMethod', new ivm.Reference(callJamfMethod));
    await jail.set('_logMessage', new ivm.Reference(logHost));

    // Compile + run the bootstrap inside the isolate (defines globals).
    const bootstrapScript = await isolate.compileScript(buildBootstrap(getAllMethodNames()));
    await bootstrapScript.run(context, { timeout: 5_000 });
    bootstrapScript.release();

    // Run user code, async-wrapped. The flat `copy: true, promise: true`
    // options instruct isolated-vm to await the resulting promise and deep-
    // copy the resolved value back to the host. This is the canonical pattern
    // documented in node_modules/isolated-vm/README.md.
    const wrapped = `"use strict";\n(async () => {\n${code}\n})()`;
    const userScript = await isolate.compileScript(wrapped, { filename: 'code-mode-execution.js' });

    let returnValue: unknown;
    try {
      // script.run uses FLAT TransferOptions (not nested under result like
      // Reference.apply). promise:true awaits the IIFE; copy:true deep-clones
      // the resolved value back to the host.
      returnValue = await userScript.run(context, {
        timeout: getTimeout(),
        promise: true,
        copy: true,
      });
    } finally {
      userScript.release();
    }

    const durationMs = Date.now() - start;
    const diffEntries = diff.getEntries();
    const blockedCommands = diffEntries.filter(
      (e) => e.action === 'command' && mode === 'apply',
    );

    // Mint an approval token if apply-mode produced blocked high-impact ops.
    if (mode === 'apply' && !approval) {
      const needsApproval = diffEntries.some((e) => e.action === 'command');
      if (needsApproval && blockedCommands.length > 0) {
        const token = crypto.randomUUID();
        pendingApprovals.set(
          token,
          blockedCommands.map((e) => ({ method: e.method, args: e.args as unknown[] })),
        );
        // Auto-expire after 5 minutes.
        const t = setTimeout(() => pendingApprovals.delete(token), 5 * 60 * 1000);
        t.unref?.();

        return {
          success: true,
          mode,
          returnValue,
          diff: diffEntries,
          logs,
          metrics: diff.getMetrics(durationMs),
          approvalRequired: { token, operations: blockedCommands },
        };
      }
    }

    if (approval) {
      pendingApprovals.delete(approval);
    }

    return {
      success: true,
      mode,
      returnValue,
      diff: diffEntries,
      logs,
      metrics: diff.getMetrics(durationMs),
    };
  } catch (err: unknown) {
    const durationMs = Date.now() - start;
    const message = err instanceof Error ? err.message : String(err);
    logs.push({ level: 'error', msg: [message] });

    return {
      success: false,
      mode,
      diff: diff.getEntries(),
      logs,
      metrics: diff.getMetrics(durationMs),
    };
  } finally {
    // ALWAYS dispose the isolate to release V8 memory.
    isolate.dispose();
  }
}
