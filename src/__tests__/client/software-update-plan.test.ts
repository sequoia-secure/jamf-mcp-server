import { describe, test, expect, jest } from '@jest/globals';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { JamfApiClientHybrid } from '../../jamf-client-hybrid.js';
import { registerTools } from '../../tools/index.js';
import { JamfAPIError } from '../../utils/errors.js';

type Handler = (request: unknown) => Promise<any>;

function setup(post: jest.Mock, readOnlyMode = false) {
  const client = new JamfApiClientHybrid({
    baseUrl: 'https://example.invalid', clientId: 'synthetic', clientSecret: 'synthetic', readOnlyMode,
  });
  const auth = jest.fn(async () => undefined);
  const internals = client as unknown as Record<string, unknown>;
  internals.axiosInstance = { post };
  internals.ensureAuthenticated = auth;
  const handlers = new Map<unknown, Handler>();
  registerTools({ setRequestHandler: (schema: unknown, handler: Handler) => handlers.set(schema, handler) } as unknown as Server,
    client);
  const call = (args: Record<string, unknown>) => handlers.get(CallToolRequestSchema)!({
    method: 'tools/call', params: { name: 'createSoftwareUpdatePlan', arguments: args },
  });
  return { client, auth, call };
}

const args = { deviceIds: ['7', '42'], updateAction: 'DOWNLOAD_ONLY', versionType: 'SPECIFIC_VERSION',
  specificVersion: '15.7', confirm: true };

describe('managed software update plan request through MCP', () => {
  test('includes COMPUTER for every targeted device and preserves version configuration', async () => {
    const post = jest.fn(async () => ({ data: { id: 'synthetic-plan' } }));
    const result = await setup(post).call(args);
    expect(result.isError).not.toBe(true);
    expect(post).toHaveBeenCalledTimes(1);
    expect(post).toHaveBeenCalledWith('/api/v1/managed-software-updates/plans', {
      devices: [{ deviceId: '7', objectType: 'COMPUTER' }, { deviceId: '42', objectType: 'COMPUTER' }],
      config: { updateAction: 'DOWNLOAD_ONLY', versionType: 'SPECIFIC_VERSION', specificVersion: '15.7' },
    });
  });

  test('does not inject a specific version for latest-version requests', async () => {
    const post = jest.fn(async () => ({ data: { id: 'synthetic-plan' } }));
    await setup(post).client.createSoftwareUpdatePlan(['7'], 'DOWNLOAD_AND_INSTALL', 'LATEST_MINOR');
    expect(post).toHaveBeenCalledWith('/api/v1/managed-software-updates/plans', {
      devices: [{ deviceId: '7', objectType: 'COMPUTER' }],
      config: { updateAction: 'DOWNLOAD_AND_INSTALL', versionType: 'LATEST_MINOR' },
    });
  });

  test.each([undefined, false])('retains the confirmation gate for confirm=%s', async confirm => {
    const post = jest.fn();
    const { call, auth } = setup(post);
    const result = await call({ ...args, confirm });
    expect(result.content[0].text).toContain('requires confirmation');
    expect(post).not.toHaveBeenCalled();
    expect(auth).not.toHaveBeenCalled();
  });

  test('retains the read-only guard', async () => {
    const post = jest.fn();
    const { call, auth } = setup(post, true);
    const result = await call(args);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('read-only mode');
    expect(post).not.toHaveBeenCalled();
    expect(auth).not.toHaveBeenCalled();
  });

  test('surfaces Jamf validation code and field through MCP without raw response values', async () => {
    const failure = Object.assign(new Error('Request failed with status code 400'), {
      isAxiosError: true,
      response: { status: 400, data: { httpStatus: 400, errors: [{
        code: 'INVALID_FIELD', field: 'devices[0].objectType', description: 'password=synthetic-secret',
      }], secret: 'synthetic-secret' } },
      config: { method: 'post', url: '/api/v1/managed-software-updates/plans',
        headers: { Authorization: 'Bearer synthetic-secret' }, data: 'synthetic-secret' },
    });
    const post = jest.fn(async () => { throw failure; });
    const result = await setup(post).call(args);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('INVALID_FIELD at devices[0].objectType');
    expect(result.content[0].text).not.toContain('synthetic-secret');
    expect(post).toHaveBeenCalledTimes(1);
  });

  test('bounds validation details and ignores malformed entries', () => {
    const error = Object.assign(new Error('Request failed'), { response: { status: 400, data: {
      errors: [null, { code: { secret: 'no' }, field: ['no'] },
        { code: 'INVALID_FIELD', field: 'devices[0].objectType' },
        { code: 'INVALID_FIELD', field: 'config.versionType' },
        { code: 'x'.repeat(500), field: 'x'.repeat(500) },
        { code: 'SHOULD_NOT_APPEAR', field: 'extra' }],
    } } });
    const result = JamfAPIError.fromAxiosError(error as any);
    expect(result.message).toContain('devices[0].objectType');
    expect(result.message).toContain('config.versionType');
    expect(result.message).not.toContain('SHOULD_NOT_APPEAR');
    expect(result.message.length).toBeLessThan(400);
  });
});
