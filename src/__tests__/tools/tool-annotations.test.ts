import { describe, test, expect, jest } from '@jest/globals';
import { CallToolRequestSchema, ListToolsRequestSchema, type Tool } from '@modelcontextprotocol/sdk/types.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { registerTools, redactLapsPasswords } from '../../tools/index.js';
import type { IJamfApiClient } from '../../types/jamf-client.js';

/**
 * A gateway in front of this server (the secops mcp-proxy) sorts tools into
 * read and write tiers by name, and those lists start from readOnlyHint. A tool
 * that ships without annotations, or with the wrong ones, is how a write or a
 * credential read lands in the read tier.
 */

type Handler = (request: unknown) => Promise<any>;

function register(client: Partial<IJamfApiClient> = {}): Map<unknown, Handler> {
  const handlers = new Map<unknown, Handler>();
  const server = {
    setRequestHandler: (schema: unknown, handler: Handler) => handlers.set(schema, handler),
  } as unknown as Server;
  registerTools(server, client as IJamfApiClient);
  return handlers;
}

async function listTools(): Promise<Tool[]> {
  const { tools } = await register().get(ListToolsRequestSchema)!({ method: 'tools/list', params: {} });
  return tools;
}

describe('tool annotations', () => {
  test('every tool declares readOnlyHint and destructiveHint', async () => {
    const missing = (await listTools())
      .filter(t => typeof t.annotations?.readOnlyHint !== 'boolean'
        || typeof t.annotations?.destructiveHint !== 'boolean')
      .map(t => t.name);
    expect(missing).toEqual([]);
  });

  test('no tool claims to be both read-only and destructive', async () => {
    const contradictory = (await listTools())
      .filter(t => t.annotations?.readOnlyHint && t.annotations?.destructiveHint)
      .map(t => t.name);
    expect(contradictory).toEqual([]);
  });

  test.each([
    // Hands out a live local admin credential.
    'getLocalAdminPassword',
    // Forces OS updates and restarts on its targets.
    'createSoftwareUpdatePlan',
  ])('%s is not read-only', async name => {
    const tool = (await listTools()).find(t => t.name === name);
    expect(tool?.annotations?.readOnlyHint).toBe(false);
  });
});

describe('LAPS audit redaction', () => {
  // Shape documented for GET /v2/local-admin-password/{id}/account/{user}/audit.
  const AUDIT = {
    totalCount: 2,
    results: [
      {
        password: 'current-secret',
        dateLastSeen: '2026-10-01T00:00:00Z',
        expirationTime: '2026-10-02T00:00:00Z',
        audits: [{ viewedBy: 'admin', dateSeen: '2026-10-01T00:00:00Z' }],
      },
      { password: 'previous-secret', dateLastSeen: null, expirationTime: null, audits: [] },
    ],
  };

  test('replaces every password and keeps the audit trail', () => {
    const redacted = redactLapsPasswords(AUDIT) as typeof AUDIT;
    expect(JSON.stringify(redacted)).not.toMatch(/secret/);
    expect(redacted.results.map(r => r.password)).toEqual(['[REDACTED]', '[REDACTED]']);
    expect(redacted.results[0].audits).toEqual(AUDIT.results[0].audits);
    expect(redacted.totalCount).toBe(2);
  });

  test('matches the key case-insensitively and at any depth', () => {
    expect(JSON.stringify(redactLapsPasswords({ a: [{ b: { Password: 'x-secret' } }] })))
      .not.toMatch(/secret/);
  });

  test('getLocalAdminPasswordAudit never returns a password', async () => {
    const getLocalAdminPasswordAudit = jest.fn(async () => AUDIT);
    const call = register({ getLocalAdminPasswordAudit } as Partial<IJamfApiClient>)
      .get(CallToolRequestSchema)!;
    const result = await call({
      method: 'tools/call',
      params: { name: 'getLocalAdminPasswordAudit', arguments: { clientManagementId: 'abc', username: 'admin' } },
    });
    expect(getLocalAdminPasswordAudit).toHaveBeenCalledWith('abc', 'admin');
    const text = result.content[0].text as string;
    expect(text).not.toMatch(/secret/);
    expect(text).toMatch(/viewedBy/);
  });
});
