import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { ApiError, ProfileResponse } from '../common/api-models';
import { CurrentUserId, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Profile, UsersService } from './users.service';

@ApiTags('users')
@ApiBearerAuth()
@Controller('me')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @ApiOperation({
    summary: 'The signed-in user and the providers linked to them',
  })
  @ApiOkResponse({ type: ProfileResponse })
  @ApiError(401, 'token_missing, token_invalid, token_expired')
  @Get()
  me(@CurrentUserId() userId: string): Promise<Profile> {
    return this.users.getProfile(userId);
  }
}
