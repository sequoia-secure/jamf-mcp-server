import { describe, test, expect } from '@jest/globals';
import type { InternalAxiosRequestConfig } from 'axios';
import { JamfApiClientHybrid } from '../../jamf-client-hybrid.js';
import { executePolicy } from '../../tools/tool-implementations.js';

/**
 * The skills wrapper passed each device id string as `deviceIds`, so the
 * client iterated it per character: `["12"]` retried the policy on computers
 * 1 and 2 instead of 12.
 */

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

describe('executePolicy (skills wrapper)', () => {
  test('multi-digit device ids reach the right computers', async () => {
    const { client, urls } = recordingClient();
    const result = await executePolicy(client, { policyId: '5', deviceIds: ['12', '305'], confirm: true });
    expect(urls).toEqual(['/api/v1/policies/5/retry/12', '/api/v1/policies/5/retry/305']);
    expect(result.summary).toEqual({ total: 2, successful: 2, failed: 0 });
  });
});

describe('JamfApiClientHybrid.executePolicy', () => {
  test('refuses a bare string for deviceIds before any request', async () => {
    const { client, urls } = recordingClient();
    await expect(client.executePolicy('5', '12' as unknown as string[])).rejects.toThrow('deviceIds must be an array');
    expect(urls).toHaveLength(0);
  });
});
