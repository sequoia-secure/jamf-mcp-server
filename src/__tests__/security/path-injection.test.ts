import { describe, test, expect } from '@jest/globals';
import type { InternalAxiosRequestConfig } from 'axios';
import { JamfApiClientHybrid } from '../../jamf-client-hybrid.js';
import { registerTools, redactPasswordText } from '../../tools/index.js';
import { pathSegment, assertSafeRequestPath } from '../../utils/url-path.js';
import type { IJamfApiClient } from '../../types/jamf-client.js';

/**
 * Caller-supplied ids are interpolated into Jamf request paths. Unencoded,
 * `<id>/account/<user>/password#` turned getLocalAdminPasswordAccounts into a
 * LAPS password read, and `../../v2/...` did the same through getScriptDetails.
 */

const MGMT_ID = '0F0E1D2C-3B4A-5968-7766-554433221100';

// Real client and interceptors; the adapter records what would hit the wire.
function recordingClient(): { client: JamfApiClientHybrid; urls: string[] } {
  const client = new JamfApiClientHybrid({
    baseUrl: 'https://example.invalid',
    clientId: 'x',
    clientSecret: 'y',
  });
  const urls: string[] = [];
  const internals = client as unknown as Record<string, any>;
  internals.ensureAuthenticated = async () => undefined;
  internals.axiosInstance.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    urls.push(config.url ?? '');
    return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
  };
  return { client, urls };
}

describe('pathSegment', () => {
  test('encodes separators and query/fragment characters', () => {
    expect(pathSegment('x/account/admin/password#')).toBe('x%2Faccount%2Fadmin%2Fpassword%23');
    expect(pathSegment('a?b')).toBe('a%3Fb');
    expect(pathSegment(42)).toBe('42');
  });

  test.each(['', '.', '..'])('rejects %j', (value) => {
    expect(() => pathSegment(value)).toThrow();
  });
});

describe('assertSafeRequestPath', () => {
  test.each([
    '/api/v1/scripts/../../v2/local-admin-password/x/account/a/password',
    '/api/v1/scripts/%2e%2e/x',
    '/api/v1/scripts/./x',
    '/api/v2/local-admin-password/x/account/a/password#/accounts',
    '/api/v2/local-admin-password/x/account/a/password?/accounts',
    '/api/v1/scripts/a\\b',
    'https://example.invalid/api/v1/scripts/../x',
  ])('rejects %s', (url) => {
    expect(() => assertSafeRequestPath(url)).toThrow();
  });

  test.each([
    '/api/v1/scripts/12',
    '/api/v1/scripts/..%2F..%2Fv2',
    '/JSSResource/computers/match/*jdoe*',
  ])('allows %s', (url) => {
    expect(() => assertSafeRequestPath(url)).not.toThrow();
  });
});

describe('JamfApiClientHybrid request paths', () => {
  test('a crafted clientManagementId cannot drop the /accounts suffix', async () => {
    const { client, urls } = recordingClient();
    await client.getLocalAdminPasswordAccounts(`${MGMT_ID}/account/admin/password#`);
    expect(urls).toHaveLength(1);
    expect(urls[0].endsWith('/accounts')).toBe(true);
    expect(urls[0]).toBe(
      `/api/v2/local-admin-password/${MGMT_ID}%2Faccount%2Fadmin%2Fpassword%23/accounts`,
    );
  });

  test('a traversing scriptId stays under /api/v1/scripts/', async () => {
    const { client, urls } = recordingClient();
    await client.getScriptDetails(`../../v2/local-admin-password/${MGMT_ID}/account/admin/password`);
    expect(urls[0].startsWith('/api/v1/scripts/')).toBe(true);
    expect(urls[0].slice('/api/v1/scripts/'.length)).not.toContain('/');
  });

  test('a bare dot-segment id is refused before any request', async () => {
    const { client, urls } = recordingClient();
    await expect(client.getScriptDetails('..')).rejects.toThrow();
    expect(urls).toHaveLength(0);
  });

  test('ordinary ids pass through unchanged', async () => {
    const { client, urls } = recordingClient();
    await client.getLocalAdminPasswordAccounts(MGMT_ID);
    await client.getScriptDetails('12');
    expect(urls).toEqual([
      `/api/v2/local-admin-password/${MGMT_ID}/accounts`,
      '/api/v1/scripts/12',
    ]);
  });
});

type CallHandler = (req: { params: { name: string; arguments: unknown } }) => Promise<any>;

function toolsWith(client: Partial<IJamfApiClient>): CallHandler {
  const handlers: CallHandler[] = [];
  const server = { setRequestHandler: (_schema: unknown, h: CallHandler) => handlers.push(h) };
  registerTools(server as any, client as IJamfApiClient);
  // registerTools installs ListTools first, then CallTool.
  return handlers[1];
}

describe('LAPS tool arguments', () => {
  const calls: string[] = [];
  const call = toolsWith({
    getLocalAdminPasswordAccounts: async (id: string) => { calls.push(id); return []; },
    getLocalAdminPasswordAudit: async (id: string) => { calls.push(id); return []; },
  });

  test.each([
    ['getLocalAdminPasswordAccounts', { clientManagementId: `${MGMT_ID}/account/admin/password#` }],
    ['getLocalAdminPasswordAudit', { clientManagementId: MGMT_ID, username: 'admin/password#' }],
    ['getLocalAdminPasswordAudit', { clientManagementId: MGMT_ID, username: '..' }],
  ])('%s rejects %j', async (name, args) => {
    const result = await call({ params: { name, arguments: args } });
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });
});

describe('read tool output', () => {
  test('never contains a password value', async () => {
    const call = toolsWith({
      getScriptDetails: async () => ({ id: '1', name: 's', password: 'hunter2' }),
      getLocalAdminPasswordAccounts: async () => [{ username: 'admin', Password: 'hunter2' }],
    } as Partial<IJamfApiClient>);
    for (const [name, args] of [
      ['getScriptDetails', { scriptId: '1' }],
      ['getLocalAdminPasswordAccounts', { clientManagementId: MGMT_ID }],
    ] as const) {
      const result = await call({ params: { name, arguments: args } });
      const text = result.content.map((c: any) => c.text).join('');
      expect(result.isError).toBeFalsy();
      expect(text).toContain('[REDACTED]');
      expect(text).not.toContain('hunter2');
    }
  });

  test('getLocalAdminPassword still returns the password once confirmed', async () => {
    const call = toolsWith({
      getLocalAdminPassword: async () => ({ password: 'hunter2' }),
    } as Partial<IJamfApiClient>);
    const result = await call({
      params: {
        name: 'getLocalAdminPassword',
        arguments: { clientManagementId: MGMT_ID, username: 'admin', confirm: true },
      },
    });
    expect(result.content[0].text).toContain('hunter2');
  });

  test('redactPasswordText handles escapes, case and non-string values', () => {
    expect(redactPasswordText('{"PASSWORD": "a\\"b", "x": 1}')).toBe('{"PASSWORD": "[REDACTED]", "x": 1}');
    expect(redactPasswordText('{"password":12345}')).toBe('{"password":"[REDACTED]"}');
    expect(redactPasswordText('{"passwordHint": "h"}')).toBe('{"passwordHint": "h"}');
  });
});
