import { Injectable } from '@nestjs/common';
import { AppError } from '../common/app-error';
import { PrismaService } from '../prisma/prisma.service';

export interface Profile {
  id: string;
  name: string;
  email: string | null;
  avatarUrl: string | null;
  providers: string[];
  createdAt: Date;
}

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async getProfile(userId: string): Promise<Profile> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        identities: {
          select: { provider: true },
          orderBy: { createdAt: 'asc' },
        },
      },
    });
    // A valid token for a user that no longer exists.
    if (!user) {
      throw AppError.unauthorized('token_invalid');
    }
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      avatarUrl: user.avatarUrl,
      providers: user.identities.map((identity) => identity.provider),
      createdAt: user.createdAt,
    };
  }
}
