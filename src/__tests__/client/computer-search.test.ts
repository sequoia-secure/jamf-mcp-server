import { describe, test, expect, jest } from '@jest/globals';
import {
  JamfApiClientHybrid,
  buildComputerSearchFilter,
  COMPUTER_SEARCH_SECTIONS,
} from '../../jamf-client-hybrid.js';

/**
 * searchDevices is how device attribution finds a Mac from a person: an email
 * or username rarely appears in the hostname, so the search has to match the
 * assigned user and return it.
 */

describe('buildComputerSearchFilter', () => {
  test('matches the computer name or the assigned user', () => {
    expect(buildComputerSearchFilter('jdoe')).toBe(
      'general.name=="*jdoe*" or userAndLocation.username=="*jdoe*"'
        + ' or userAndLocation.email=="*jdoe*" or userAndLocation.realname=="*jdoe*"',
    );
  });

  test('escapes quotes so the query cannot rewrite the filter', () => {
    const filter = buildComputerSearchFilter('x" or general.name=="*');
    // Every quote from the query is escaped; only the builder's own quotes are bare.
    expect(filter.replace(/\\"/g, '').match(/"/g)).toHaveLength(8);
  });

  test('escapes backslashes before quotes', () => {
    expect(buildComputerSearchFilter('a\\"b')).toContain('"*a\\\\\\"b*"');
  });

  test('trims the query', () => {
    expect(buildComputerSearchFilter('  jdoe ')).toContain('general.name=="*jdoe*"');
  });
});

function clientWith(get: jest.Mock): JamfApiClientHybrid {
  const client = new JamfApiClientHybrid({
    baseUrl: 'https://example.invalid',
    clientId: 'x',
    clientSecret: 'y',
  });
  const internals = client as unknown as Record<string, unknown>;
  internals.axiosInstance = { get };
  internals.ensureAuthenticated = async () => undefined;
  return client;
}

describe('searchComputers on the Jamf Pro API', () => {
  test('requests the user, hardware and OS sections and returns the assigned user', async () => {
    const get = jest.fn(async () => ({
      data: {
        results: [{
          id: '7',
          general: { name: 'JDOE-MBP16', udid: 'u', serialNumber: 'S1' },
          userAndLocation: { username: 'jdoe', email: 'jdoe@example.com', realname: 'Jane Doe' },
          hardware: { modelIdentifier: 'Mac15,9' },
          operatingSystem: { version: '15.1' },
        }],
      },
    }));
    const [device] = await clientWith(get).searchComputers('jdoe@example.com', 10);

    const [path, { params }] = get.mock.calls[0] as unknown as [string, { params: URLSearchParams }];
    expect(path).toBe('/api/v1/computers-inventory');
    expect(params.getAll('section')).toEqual(COMPUTER_SEARCH_SECTIONS);
    expect(params.get('page-size')).toBe('10');
    expect(params.get('filter')).toBe(buildComputerSearchFilter('jdoe@example.com'));

    expect(device).toMatchObject({
      id: '7',
      name: 'JDOE-MBP16',
      username: 'jdoe',
      email: 'jdoe@example.com',
      realName: 'Jane Doe',
      modelIdentifier: 'Mac15,9',
      osVersion: '15.1',
    });
  });

  test('sends no filter for an empty query', async () => {
    const get = jest.fn(async () => ({ data: { results: [] } }));
    await clientWith(get).searchComputers('  ', 5);
    const [, { params }] = get.mock.calls[0] as unknown as [string, { params: URLSearchParams }];
    expect(params.has('filter')).toBe(false);
  });

  test('a rejected filter falls back to the Classic match endpoint, which searches users', async () => {
    const get = jest.fn(async (path: string) => {
      if (path === '/api/v1/computers-inventory') {
        throw Object.assign(new Error('400'), { response: { status: 400 } });
      }
      return { data: { computers: [{ id: 3, name: 'mbp', username: 'jdoe', email_address: 'jdoe@example.com' }] } };
    });
    const [device] = await clientWith(get as unknown as jest.Mock).searchComputers('jdoe', 10);
    expect(get.mock.calls[1][0]).toBe('/JSSResource/computers/match/*jdoe*');
    expect(device).toMatchObject({ id: '3', username: 'jdoe', email: 'jdoe@example.com' });
  });
});
