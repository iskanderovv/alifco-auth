import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';

@Controller('health')
@SkipThrottle()
export class HealthController {
  /** Liveness only: no database call, so a DB outage does not make the platform restart the app. */
  @Get()
  check(): { status: 'ok' } {
    return { status: 'ok' };
  }
}
