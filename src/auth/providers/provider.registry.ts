import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppError } from '../../common/app-error';
import type { Env } from '../../config/env';
import { FacebookProvider } from './facebook.provider';
import { GoogleProvider } from './google.provider';
import type { OAuthProvider } from './oauth-provider.interface';

/**
 * The providers that are configured. A provider with no credentials is simply absent, so the
 * service still boots with only Google set up and the others return 404.
 * Adding a provider: write one adapter, register it here.
 */
@Injectable()
export class ProviderRegistry {
  private readonly logger = new Logger(ProviderRegistry.name);
  private readonly providers = new Map<string, OAuthProvider>();

  constructor(config: ConfigService<Env, true>) {
    const apiBaseUrl = config.get('API_BASE_URL', { infer: true });
    const timeoutMs = config.get('HTTP_TIMEOUT_MS', { infer: true });

    const googleId = config.get('GOOGLE_CLIENT_ID', { infer: true });
    const googleSecret = config.get('GOOGLE_CLIENT_SECRET', { infer: true });
    if (googleId && googleSecret) {
      this.register(
        new GoogleProvider({
          clientId: googleId,
          clientSecret: googleSecret,
          redirectUri: `${apiBaseUrl}/auth/google/callback`,
          timeoutMs,
        }),
      );
    }

    const facebookId = config.get('FACEBOOK_APP_ID', { infer: true });
    const facebookSecret = config.get('FACEBOOK_APP_SECRET', { infer: true });
    if (facebookId && facebookSecret) {
      this.register(
        new FacebookProvider({
          appId: facebookId,
          appSecret: facebookSecret,
          graphVersion: config.get('FACEBOOK_GRAPH_VERSION', { infer: true }),
          redirectUri: `${apiBaseUrl}/auth/facebook/callback`,
          timeoutMs,
        }),
      );
    }

    this.logger.log(
      `Enabled providers: ${[...this.providers.keys()].join(', ') || 'none'}`,
    );
  }

  get(name: string): OAuthProvider {
    const provider = this.providers.get(name);
    if (!provider) {
      throw new AppError('provider_not_found', 404);
    }
    return provider;
  }

  private register(provider: OAuthProvider): void {
    this.providers.set(provider.name, provider);
  }
}
