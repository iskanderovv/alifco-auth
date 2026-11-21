/**
 * Stable machine-readable error codes. Clients depend on these, messages may change.
 * See docs/API.md for the response format.
 */
export type ErrorCode =
  | 'token_missing'
  | 'token_invalid'
  | 'token_expired'
  | 'refresh_missing'
  | 'refresh_invalid'
  | 'refresh_expired'
  | 'refresh_reused'
  | 'csrf_header_missing'
  | 'csrf_origin_invalid'
  | 'rate_limited'
  | 'not_found'
  | 'payload_too_large'
  | 'invalid_state'
  | 'provider_not_found'
  | 'provider_error'
  | 'access_denied'
  | 'identity_taken'
  | 'already_linked'
  | 'not_linked'
  | 'last_identity'
  | 'validation_failed'
  | 'internal_error';

export class AppError extends Error {
  constructor(
    readonly code: ErrorCode,
    readonly status: number,
    message: string = code,
  ) {
    super(message);
    this.name = 'AppError';
  }

  static unauthorized(code: ErrorCode, message?: string): AppError {
    return new AppError(code, 401, message);
  }
}
