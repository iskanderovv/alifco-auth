import { Controller, Get, UseGuards } from '@nestjs/common';
import { CurrentUserId, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Profile, UsersService } from './users.service';

@Controller('me')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  me(@CurrentUserId() userId: string): Promise<Profile> {
    return this.users.getProfile(userId);
  }
}
