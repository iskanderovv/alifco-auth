import { ApiProperty, ApiResponse } from '@nestjs/swagger';

class ErrorBody {
  @ApiProperty({ example: 'token_invalid' })
  code: string;

  @ApiProperty({ example: 'token_invalid' })
  message: string;
}

export class ErrorResponse {
  @ApiProperty({ type: ErrorBody })
  error: ErrorBody;
}

export class AccessTokenResponse {
  @ApiProperty({ description: 'Send as "Authorization: Bearer <token>"' })
  accessToken: string;

  @ApiProperty({ example: 900, description: 'Seconds until it expires' })
  expiresIn: number;
}

export class ProfileResponse {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ example: 'Ali Valiyev' })
  name: string;

  @ApiProperty({
    nullable: true,
    type: String,
    description: 'Only set when the provider verified it',
  })
  email: string | null;

  @ApiProperty({ nullable: true, type: String })
  avatarUrl: string | null;

  @ApiProperty({ type: [String], example: ['google', 'telegram'] })
  providers: string[];

  @ApiProperty({ format: 'date-time' })
  createdAt: string;
}

export class LinkUrlResponse {
  @ApiProperty({ description: 'Navigate the browser here to finish linking' })
  url: string;
}

export class HealthResponse {
  @ApiProperty({ example: 'ok' })
  status: string;
}

export const ApiError = (status: number, codes: string) =>
  ApiResponse({ status, type: ErrorResponse, description: codes });
