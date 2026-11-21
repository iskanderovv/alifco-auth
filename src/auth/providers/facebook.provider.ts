import { createHmac } from 'node:crypto';
import { OAuthProvider as ProviderName } from '../../generated/prisma/enums';
import type { OAuthProfile, OAuthProvider } from './oauth-provider.interface';
import { asString, providerError } from './oidc';

export interface FacebookProviderOptions {
  appId: string;
  appSecret: string;
  /** For example `v25.0`. Pinned so a Graph API upgrade cannot change behavior silently. */
  graphVersion: string;
  /** Built from API_BASE_URL, never from the request. Must match the Meta console exactly. */
  redirectUri: string;
  timeoutMs: number;
  /** Injectable so tests never touch the network. */
  fetchFn?: typeof fetch;
}

/**
 * Facebook Login, authorization code flow with PKCE (S256), then Graph API `/me`.
 *
 * Facebook gives no `email_verified` claim, so `emailVerified` is always false: the email is
 * kept on the identity for reference and is never used to match or merge accounts.
 * The Graph API id is the stable identifier, never the email.
 *
 * Every Graph call carries `appsecret_proof`, so a leaked access token is useless without the
 * app secret. Secrets go in the POST body, not in a URL.
 */
export class FacebookProvider implements OAuthProvider {
  readonly name = ProviderName.facebook;

  private readonly fetchFn: typeof fetch;

  constructor(private readonly options: FacebookProviderOptions) {
    this.fetchFn = options.fetchFn ?? fetch;
  }

  getAuthorizationUrl(state: string, codeChallenge: string): string {
    const url = new URL(
      `https://www.facebook.com/${this.options.graphVersion}/dialog/oauth`,
    );
    url.search = new URLSearchParams({
      client_id: this.options.appId,
      redirect_uri: this.options.redirectUri,
      response_type: 'code',
      scope: 'public_profile,email',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    }).toString();
    return url.toString();
  }

  async authenticate(input: {
    code: string;
    codeVerifier: string;
  }): Promise<OAuthProfile> {
    const accessToken = await this.exchangeCode(input);
    const me = await this.fetchProfile(accessToken);

    const id = typeof me.id === 'string' ? me.id : undefined;
    if (!id) {
      throw providerError('Facebook profile has no id');
    }
    return {
      providerUserId: id,
      email: asString(me.email),
      emailVerified: false,
      name: asString(me.name),
      avatarUrl: asString(me.picture?.data?.url),
    };
  }

  private graphUrl(path: string): string {
    return `https://graph.facebook.com/${this.options.graphVersion}${path}`;
  }

  private async exchangeCode(input: {
    code: string;
    codeVerifier: string;
  }): Promise<string> {
    const body = await this.request(
      this.graphUrl('/oauth/access_token'),
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: this.options.appId,
          client_secret: this.options.appSecret,
          redirect_uri: this.options.redirectUri,
          code: input.code,
          code_verifier: input.codeVerifier,
        }),
      },
      'token request',
    );
    const token = (body as { access_token?: unknown } | null)?.access_token;
    if (typeof token !== 'string' || !token) {
      throw providerError('Facebook response has no access_token');
    }
    return token;
  }

  private async fetchProfile(accessToken: string): Promise<FacebookMe> {
    const url = new URL(this.graphUrl('/me'));
    url.search = new URLSearchParams({
      fields: 'id,name,email,picture.type(large)',
      access_token: accessToken,
      appsecret_proof: createHmac('sha256', this.options.appSecret)
        .update(accessToken)
        .digest('hex'),
    }).toString();

    const body = await this.request(
      url.toString(),
      { method: 'GET' },
      'profile request',
    );
    return body ?? {};
  }

  /** One place for timeout, status handling and JSON parsing. Response bodies are never copied into errors. */
  private async request(
    url: string,
    init: RequestInit,
    what: string,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchFn(url, {
        ...init,
        headers: { accept: 'application/json', ...init.headers },
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch {
      throw providerError(`Facebook ${what} failed`);
    }
    if (!response.ok) {
      throw providerError(`Facebook ${what} returned ${response.status}`);
    }
    return response.json().catch(() => null) as Promise<unknown>;
  }
}

interface FacebookMe {
  id?: unknown;
  name?: unknown;
  email?: unknown;
  picture?: { data?: { url?: unknown } };
}
