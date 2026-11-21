import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { CookieService } from './cookies.service';
import { CsrfGuard } from './guards/csrf.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IdentityService } from './identity/identity.service';
import { OAuthTransactionService } from './oauth/oauth-transaction.service';
import { ProviderRegistry } from './providers/provider.registry';
import { TokenService } from './tokens/token.service';

@Module({
  controllers: [AuthController],
  providers: [
    TokenService,
    OAuthTransactionService,
    IdentityService,
    ProviderRegistry,
    CookieService,
    CsrfGuard,
    JwtAuthGuard,
  ],
  exports: [TokenService, JwtAuthGuard],
})
export class AuthModule {}
