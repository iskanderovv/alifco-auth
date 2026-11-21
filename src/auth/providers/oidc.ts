import { errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { AppError } from '../../common/app-error';

/** Tolerated difference between our clock and the provider's, in seconds. */
const CLOCK_TOLERANCE_SECONDS = 30;

export function providerError(message: string): AppError {
  return new AppError('provider_error', 502, message);
}

export function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined;
}

/**
 * The standard OAuth `error` code (invalid_client, invalid_grant, ...) of a failed token
 * response, for diagnosis. Only a short lowercase identifier is accepted; the rest of the body
 * (descriptions, echoed request values) is never copied.
 */
function oauthErrorCode(body: unknown): string {
  const code = asString((body as { error?: unknown } | null)?.error);
  return code && /^[a-z_]{1,40}$/.test(code) ? ` (${code})` : '';
}

/** Which check failed (for example the claim name), never the values. */
function describeJoseError(error: unknown): string {
  if (error instanceof errors.JWTClaimValidationFailed) {
    return ` (${error.code}: claim ${error.claim})`;
  }
  if (error instanceof errors.JOSEError) {
    return ` (${error.code})`;
  }
  return '';
}

export interface TokenRequest {
  fetchFn: typeof fetch;
  url: string;
  body: URLSearchParams;
  /** For providers that authenticate the client with HTTP Basic instead of body fields. */
  basicAuth?: { clientId: string; clientSecret: string };
  timeoutMs: number;
  /** Only used in error messages. */
  provider: string;
}

/**
 * Authorization code exchange at an OIDC token endpoint. Returns the `id_token`.
 * Response bodies are never copied into errors: they can echo request values.
 */
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
  /** Keys come from the provider's JWKS URL that we configure, never from the token itself. */
  getKey: JWTVerifyGetKey;
  issuer: string | string[];
  audience: string;
  /** Pinned: any other algorithm, including `none`, is rejected. */
  algorithms: string[];
  provider: string;
}

/** Verifies signature, issuer, audience and expiry (`exp`, and `nbf` when present). */
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
    throw providerError(
      `${check.provider} id_token failed verification${describeJoseError(error)}`,
    );
  }
}
