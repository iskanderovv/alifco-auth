import {
  createLocalJWKSet,
  errors,
  jwtVerify,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';
import { AppError } from '../../common/app-error';

const CLOCK_TOLERANCE_SECONDS = 30;
const JWKS_TTL_MS = 10 * 60 * 1000;
const JWKS_COOLDOWN_MS = 30 * 1000;

export function providerError(message: string): AppError {
  return new AppError('provider_error', 502, message);
}

export function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined;
}

// Only the standard error code is copied into errors, never the response body.
function oauthErrorCode(body: unknown): string {
  const code = asString((body as { error?: unknown } | null)?.error);
  return code && /^[a-z_]{1,40}$/.test(code) ? ` (${code})` : '';
}

function describeJoseError(error: unknown): string {
  if (error instanceof errors.JWTClaimValidationFailed) {
    return ` (${error.code}: claim ${error.claim})`;
  }
  if (error instanceof errors.JOSEError) {
    return ` (${error.code}: ${error.message})`;
  }
  return '';
}

export interface TokenRequest {
  fetchFn: typeof fetch;
  url: string;
  body: URLSearchParams;
  basicAuth?: { clientId: string; clientSecret: string };
  timeoutMs: number;
  provider: string;
}

export async function requestIdToken(request: TokenRequest): Promise<string> {
  const headers: Record<string, string> = {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
  };
  if (request.basicAuth) {
    const { clientId, clientSecret } = request.basicAuth;
    headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  }

  let response: Response;
  try {
    response = await request.fetchFn(request.url, {
      method: 'POST',
      headers,
      body: request.body,
      signal: AbortSignal.timeout(request.timeoutMs),
    });
  } catch {
    throw providerError(`${request.provider} token request failed`);
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw providerError(
      `${request.provider} token endpoint returned ${response.status}${oauthErrorCode(body)}`,
    );
  }
  const idToken = asString((body as { id_token?: unknown } | null)?.id_token);
  if (!idToken) {
    throw providerError(`${request.provider} response has no id_token`);
  }
  return idToken;
}

export interface IdTokenCheck {
  idToken: string;
  getKey: JWTVerifyGetKey;
  issuer: string | string[];
  audience: string;
  algorithms: string[];
  provider: string;
}

export async function verifyIdToken(check: IdTokenCheck): Promise<JWTPayload> {
  try {
    const { payload } = await jwtVerify(check.idToken, check.getKey, {
      algorithms: check.algorithms,
      issuer: check.issuer,
      audience: check.audience,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    return payload;
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    throw providerError(
      `${check.provider} id_token failed verification${describeJoseError(error)}`,
    );
  }
}

// Loaded with fetch, not jose's own loader: that one does not decompress, and Telegram
// answers the key request with gzip even when none is asked for.
export function remoteJwks(
  url: string,
  timeoutMs: number,
  fetchFn: typeof fetch = fetch,
): JWTVerifyGetKey {
  let keys: JWK[] = [];
  let loadedAt = 0;
  let inFlight: Promise<void> | undefined;

  const load = (): Promise<void> => {
    inFlight ??= (async () => {
      let response: Response;
      try {
        response = await fetchFn(url, {
          headers: { accept: 'application/json' },
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch {
        throw providerError('Signing keys request failed');
      }
      if (!response.ok) {
        throw providerError(`Signing keys request returned ${response.status}`);
      }
      const body: unknown = await response.json().catch(() => null);
      const list = (body as { keys?: unknown } | null)?.keys;
      if (!Array.isArray(list)) {
        throw providerError('Signing keys response is malformed');
      }
      keys = list as JWK[];
      loadedAt = Date.now();
    })().finally(() => {
      inFlight = undefined;
    });
    return inFlight;
  };

  return async (header, token) => {
    if (loadedAt === 0 || Date.now() - loadedAt > JWKS_TTL_MS) {
      await load();
    }
    try {
      return await createLocalJWKSet({ keys })(header, token);
    } catch (error) {
      // A new key may have been published: look again, but not on every bad token.
      if (
        error instanceof errors.JWKSNoMatchingKey &&
        Date.now() - loadedAt > JWKS_COOLDOWN_MS
      ) {
        await load();
        return createLocalJWKSet({ keys })(header, token);
      }
      throw error;
    }
  };
}
