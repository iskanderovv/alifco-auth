import type { OAuthProfile } from '../auth/providers/oauth-provider.interface';

const NAME_MAX = 255;
const EMAIL_MAX = 320;
const FALLBACK_NAME = 'User';

export function normalizeEmail(email: string | undefined): string | undefined {
  const value = email?.trim().toLowerCase();
  if (!value || value.length > EMAIL_MAX || !value.includes('@')) {
    return undefined;
  }
  return value;
}

export function displayName(profile: OAuthProfile): string {
  const candidate = [profile.name, profile.username]
    .map((value) => value?.trim())
    .find((value) => value);
  return (candidate ?? FALLBACK_NAME).slice(0, NAME_MAX);
}

export function safeAvatarUrl(url: string | undefined): string | undefined {
  if (!url) {
    return undefined;
  }
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}
