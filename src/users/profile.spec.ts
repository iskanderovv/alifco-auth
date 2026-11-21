import { displayName, normalizeEmail, safeAvatarUrl } from './profile';

describe('normalizeEmail', () => {
  it('trims and lowercases', () => {
    expect(normalizeEmail('  Ali@Gmail.COM ')).toBe('ali@gmail.com');
  });

  it.each([undefined, '', '   ', 'no-at-sign', `${'a'.repeat(320)}@x.com`])(
    'returns undefined for %p',
    (value) => {
      expect(normalizeEmail(value)).toBeUndefined();
    },
  );
});

describe('displayName', () => {
  const base = { providerUserId: '1', emailVerified: false };

  it('prefers the name, then the username, then a fallback', () => {
    expect(displayName({ ...base, name: 'Ali Valiyev', username: 'ali' })).toBe(
      'Ali Valiyev',
    );
    expect(displayName({ ...base, name: '  ', username: 'ali' })).toBe('ali');
    expect(displayName(base)).toBe('User');
  });

  it('truncates to the column length', () => {
    expect(displayName({ ...base, name: 'x'.repeat(1000) })).toHaveLength(255);
  });
});

describe('safeAvatarUrl', () => {
  it('keeps https URLs', () => {
    expect(safeAvatarUrl('https://example.com/a.png')).toBe(
      'https://example.com/a.png',
    );
  });

  it.each([
    'http://example.com/a.png',
    'javascript:alert(1)',
    'data:image/png;base64,AAAA',
    'not a url',
    '',
    undefined,
  ])('rejects %p', (value) => {
    expect(safeAvatarUrl(value)).toBeUndefined();
  });
});
