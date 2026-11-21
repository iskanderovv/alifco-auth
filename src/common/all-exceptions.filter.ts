import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  Logger,
} from '@nestjs/common';
import { ThrottlerException } from '@nestjs/throttler';
import type { Response } from 'express';
import { AppError, ErrorCode } from './app-error';

interface Described {
  status: number;
  code: ErrorCode;
  message: string;
}

function isHttpError(
  value: unknown,
): value is { status: number; type?: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { status?: unknown }).status === 'number'
  );
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<Response>();
    const { status, code, message } = this.describe(exception);

    if (status >= 500) {
      this.logger.error(
        exception instanceof Error
          ? (exception.stack ?? exception.message)
          : String(exception),
      );
    }
    response.status(status).json({ error: { code, message } });
  }

  private describe(exception: unknown): Described {
    if (exception instanceof AppError) {
      return {
        status: exception.status,
        code: exception.code,
        message: exception.message,
      };
    }
    if (exception instanceof ThrottlerException) {
      return {
        status: 429,
        code: 'rate_limited',
        message: 'Too many requests',
      };
    }
    if (exception instanceof HttpException) {
      return this.fromStatus(exception.getStatus());
    }
    if (
      isHttpError(exception) &&
      exception.status >= 400 &&
      exception.status < 500
    ) {
      return this.fromStatus(exception.status);
    }
    return {
      status: 500,
      code: 'internal_error',
      message: 'Internal server error',
    };
  }

  private fromStatus(status: number): Described {
    switch (status) {
      case 404:
        return { status, code: 'not_found', message: 'Not found' };
      case 413:
        return {
          status,
          code: 'payload_too_large',
          message: 'Payload too large',
        };
      case 429:
        return { status, code: 'rate_limited', message: 'Too many requests' };
      case 400:
        return {
          status,
          code: 'validation_failed',
          message: 'Invalid request',
        };
      default:
        return status >= 500
          ? { status, code: 'internal_error', message: 'Internal server error' }
          : { status, code: 'validation_failed', message: 'Invalid request' };
    }
  }
}
