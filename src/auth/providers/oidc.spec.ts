import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
import { createRemoteJWKSet, exportJWK, generateKeyPair, type JWK } from 'jose';
import { remoteJwks } from './oidc';

const HEADER = { alg: 'RS256', kid: 'key-1' };
const TOKEN = { payload: {} } as never;

let jwk1: JWK;
let jwk2: JWK;

beforeAll(async () => {
  for (const kid of ['key-1', 'key-2']) {
    const { publicKey } = await generateKeyPair('RS256');
    const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256' };
    if (kid === 'key-1') jwk1 = jwk;
    else jwk2 = jwk;
  }
});

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

describe('remoteJwks', () => {
  it('fetches the keys once and serves later calls from memory', async () => {
    const fetchFn = jest.fn().mockResolvedValue(jsonResponse({ keys: [jwk1] }));
    const getKey = remoteJwks('https://keys.test/jwks', 1000, fetchFn);

    await getKey(HEADER, TOKEN);
    await getKey(HEADER, TOKEN);

    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('shares one request between concurrent callers', async () => {
    const fetchFn = jest.fn().mockResolvedValue(jsonResponse({ keys: [jwk1] }));
    const getKey = remoteJwks('https://keys.test/jwks', 1000, fetchFn);

    await Promise.all([
      getKey(HEADER, TOKEN),
      getKey(HEADER, TOKEN),
      getKey(HEADER, TOKEN),
    ]);

    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('does not look again on every unknown key id, only after the cooldown', async () => {
    const fetchFn = jest.fn().mockResolvedValue(jsonResponse({ keys: [jwk1] }));
    const getKey = remoteJwks('https://keys.test/jwks', 1000, fetchFn);
    const unknown = { alg: 'RS256', kid: 'key-2' };

    await getKey(HEADER, TOKEN);
    await expect(getKey(unknown, TOKEN)).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);

    const realNow = Date.now();
    const spy = jest.spyOn(Date, 'now').mockReturnValue(realNow + 31_000);
    fetchFn.mockResolvedValue(jsonResponse({ keys: [jwk1, jwk2] }));
    await expect(getKey(unknown, TOKEN)).resolves.toBeDefined();
    expect(fetchFn).toHaveBeenCalledTimes(2);
    spy.mockRestore();
  });

  it('asks for JSON with a timeout', async () => {
    const fetchFn = jest.fn().mockResolvedValue(jsonResponse({ keys: [jwk1] }));
    await remoteJwks('https://keys.test/jwks', 1000, fetchFn)(HEADER, TOKEN);

    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://keys.test/jwks');
    expect((init.headers as Record<string, string>).accept).toBe(
      'application/json',
    );
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  describe('fails with provider_error', () => {
    const getKeyWith = (fetchFn: typeof fetch) =>
      remoteJwks('https://keys.test/jwks', 1000, fetchFn);

    it('on a non-200 answer, naming the status', async () => {
      const fetchFn = jest.fn().mockResolvedValue(jsonResponse({}, 503));
      await expect(getKeyWith(fetchFn)(HEADER, TOKEN)).rejects.toMatchObject({
        code: 'provider_error',
        message: expect.stringContaining('503') as string,
      });
    });

    it('on a body that is not JSON', async () => {
      const fetchFn = jest.fn().mockResolvedValue(new Response('<html>'));
      await expect(getKeyWith(fetchFn)(HEADER, TOKEN)).rejects.toMatchObject({
        code: 'provider_error',
      });
    });

    it('on JSON without a keys array', async () => {
      const fetchFn = jest.fn().mockResolvedValue(jsonResponse({ keys: 'no' }));
      await expect(getKeyWith(fetchFn)(HEADER, TOKEN)).rejects.toMatchObject({
        code: 'provider_error',
      });
    });

    it('on a network failure', async () => {
      const fetchFn = jest.fn().mockRejectedValue(new Error('ECONNRESET'));
      await expect(getKeyWith(fetchFn)(HEADER, TOKEN)).rejects.toMatchObject({
        code: 'provider_error',
      });
    });

    it('and tries again on the next call instead of caching the failure', async () => {
      const fetchFn = jest
        .fn()
        .mockResolvedValueOnce(jsonResponse({}, 500))
        .mockResolvedValueOnce(jsonResponse({ keys: [jwk1] }));
      const getKey = getKeyWith(fetchFn);

      await expect(getKey(HEADER, TOKEN)).rejects.toBeDefined();
      await expect(getKey(HEADER, TOKEN)).resolves.toBeDefined();
    });
  });

  describe('against a server that always gzips, like Telegram', () => {
    let server: Server;
    let url: string;

    beforeAll(async () => {
      server = createServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/json',
          'content-encoding': 'gzip',
        });
        res.end(gzipSync(JSON.stringify({ keys: [jwk1] })));
      });
      await new Promise<void>((resolve) => server.listen(0, resolve));
      url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks`;
    });

    afterAll(async () => {
      await new Promise((resolve) => server.close(resolve));
    });

    it('reads the keys', async () => {
      await expect(remoteJwks(url, 2000)(HEADER, TOKEN)).resolves.toBeDefined();
    });

    it('is the case that jose’s own loader cannot read', async () => {
      const joseLoader = createRemoteJWKSet(new URL(url), {
        timeoutDuration: 2000,
      });
      await expect(joseLoader(HEADER, TOKEN)).rejects.toThrow(
        /Failed to parse the JSON Web Key Set HTTP response as JSON/,
      );
    });
  });
});
