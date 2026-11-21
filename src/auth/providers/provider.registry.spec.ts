import { ProviderRegistry } from './provider.registry';
import { fakeConfig } from '../../../test/helpers/db';

const base = {
  API_BASE_URL: 'http://localhost:3000',
  HTTP_TIMEOUT_MS: 1000,
  FACEBOOK_GRAPH_VERSION: 'v25.0',
};

describe('ProviderRegistry', () => {
  it('registers nothing without credentials, so every provider is 404', () => {
    const registry = new ProviderRegistry(fakeConfig(base));
    for (const name of ['google', 'facebook', 'telegram', 'myspace']) {
      expect(() => registry.get(name)).toThrow(
        expect.objectContaining({ code: 'provider_not_found', status: 404 }),
      );
    }
  });

  it('registers only the providers that have credentials', () => {
    const registry = new ProviderRegistry(
      fakeConfig({
        ...base,
        GOOGLE_CLIENT_ID: 'id',
        GOOGLE_CLIENT_SECRET: 'secret',
      }),
    );
    expect(registry.get('google').name).toBe('google');
    expect(() => registry.get('facebook')).toThrow(
      expect.objectContaining({ code: 'provider_not_found' }),
    );
  });

  it('registers Facebook with its own callback URL and Graph version', () => {
    const registry = new ProviderRegistry(
      fakeConfig({
        ...base,
        FACEBOOK_APP_ID: 'app',
        FACEBOOK_APP_SECRET: 'secret',
      }),
    );
    const url = new URL(registry.get('facebook').getAuthorizationUrl('s', 'c'));
    expect(url.pathname).toBe('/v25.0/dialog/oauth');
    expect(url.searchParams.get('redirect_uri')).toBe(
      'http://localhost:3000/auth/facebook/callback',
    );
  });

  it('registers Telegram with its own callback URL', () => {
    const registry = new ProviderRegistry(
      fakeConfig({
        ...base,
        TELEGRAM_CLIENT_ID: '123',
        TELEGRAM_CLIENT_SECRET: 'secret',
      }),
    );
    const url = new URL(registry.get('telegram').getAuthorizationUrl('s', 'c'));
    expect(url.origin).toBe('https://oauth.telegram.org');
    expect(url.searchParams.get('redirect_uri')).toBe(
      'http://localhost:3000/auth/telegram/callback',
    );
  });

  it('does not accept inherited object keys as provider names', () => {
    const registry = new ProviderRegistry(fakeConfig(base));
    for (const name of ['constructor', '__proto__', 'toString']) {
      expect(() => registry.get(name)).toThrow(
        expect.objectContaining({ code: 'provider_not_found' }),
      );
    }
  });
});
