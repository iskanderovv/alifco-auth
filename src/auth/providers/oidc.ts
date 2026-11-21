import { errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { AppError } from '../../common/app-error';

const CLOCK_TOLERANCE_SECONDS = 30;

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
    return ` (${error.code})`;
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
    throw providerError(
      `${check.provider} id_token failed verification${describeJoseError(error)}`,
    );
  }
}
