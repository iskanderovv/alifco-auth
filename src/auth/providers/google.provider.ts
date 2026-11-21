import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { AppError } from '../../common/app-error';
import { OAuthProvider as ProviderName } from '../../generated/prisma/enums';
import type { OAuthProfile, OAuthProvider } from './oauth-provider.interface';

const AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export interface GoogleProviderOptions {
  clientId: string;
  clientSecret: string;
  /** Built from API_BASE_URL, never from the request. Must match the Google console exactly. */
  redirectUri: string;
  timeoutMs: number;
  /** Injectable so tests never touch the network. */
  fetchFn?: typeof fetch;
  getKey?: JWTVerifyGetKey;
}

/**
 * Google, OpenID Connect authorization code flow with PKCE (S256).
 *
 * The profile comes from the `id_token` returned by Google's token endpoint. It is fetched
 * server to server over TLS with our client secret and the PKCE verifier, and its signature,
 * issuer, audience and expiry are verified anyway. No `nonce` is used: the token never passes
 * through the browser, so there is nothing to replay (`state` and PKCE cover the redirect).
 */
export class GoogleProvider implements OAuthProvider {
  readonly name = ProviderName.google;

  private readonly fetchFn: typeof fetch;
  private readonly getKey: JWTVerifyGetKey;

  constructor(private readonly options: GoogleProviderOptions) {
    this.fetchFn = options.fetchFn ?? fetch;
    this.getKey =
      options.getKey ??
      createRemoteJWKSet(new URL(JWKS_URL), {
        timeoutDuration: options.timeoutMs,
        cooldownDuration: 30_000,
      });
  }

  getAuthorizationUrl(state: string, codeChallenge: string): string {
    const url = new URL(AUTHORIZATION_URL);
    url.search = new URLSearchParams({
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      // Always show the account chooser instead of silently reusing the last account.
      prompt: 'select_account',
    }).toString();
    return url.toString();
  }

  async authenticate(input: {
    code: string;
    codeVerifier: string;
  }): Promise<OAuthProfile> {
    const idToken = await this.exchangeCode(input);
    const claims = await this.verifyIdToken(idToken);

    if (typeof claims.sub !== 'string' || !claims.sub) {
      throw providerError('Google id_token has no subject');
    }
    return {
      providerUserId: claims.sub,
      email: asString(claims.email),
      // Google sends a boolean, some older tokens a string.
      emailVerified:
        claims.email_verified === true || claims.email_verified === 'true',
      name: asString(claims.name),
      avatarUrl: asString(claims.picture),
    };
  }

  private async exchangeCode(input: {
    code: string;
    codeVerifier: string;
  }): Promise<string> {
    let response: Response;
    try {
      response = await this.fetchFn(TOKEN_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: input.code,
          redirect_uri: this.options.redirectUri,
          client_id: this.options.clientId,
          client_secret: this.options.clientSecret,
          code_verifier: input.codeVerifier,
        }),
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch {
      throw providerError('Google token request failed');
    }

    // The response body is never copied into an error: it can echo request values.
    if (!response.ok) {
      throw providerError(`Google token endpoint returned ${response.status}`);
    }
    const body: unknown = await response.json().catch(() => null);
    const idToken = (body as { id_token?: unknown } | null)?.id_token;
    if (typeof idToken !== 'string' || !idToken) {
      throw providerError('Google response has no id_token');
    }
    return idToken;
  }

  private async verifyIdToken(idToken: string) {
    try {
      const { payload } = await jwtVerify(idToken, this.getKey, {
        algorithms: ['RS256'],
        issuer: ISSUERS,
        audience: this.options.clientId,
      });
      return payload;
    } catch {
      throw providerError('Google id_token failed verification');
    }
  }
}

function providerError(message: string): AppError {
  return new AppError('provider_error', 502, message);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined;
}
