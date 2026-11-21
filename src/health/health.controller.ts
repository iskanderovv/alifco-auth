import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { SkipThrottle } from '@nestjs/throttler';
import { HealthResponse } from '../common/api-models';

@ApiTags('health')
@Controller('health')
@SkipThrottle()
export class HealthController {
  @ApiOperation({ summary: 'Liveness check, does not touch the database' })
  @ApiOkResponse({ type: HealthResponse })
  @Get()
  check(): { status: 'ok' } {
    return { status: 'ok' };
  }
}
