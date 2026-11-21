import { Injectable } from '@nestjs/common';
import { AppError } from '../../common/app-error';
import {
  isUuid,
  pkceChallenge,
  randomToken,
  sha256Hex,
} from '../../common/crypto';
import { OAuthMode, OAuthProvider } from '../../generated/prisma/enums';
import { PrismaService } from '../../prisma/prisma.service';

export const OAUTH_TX_COOKIE = 'oauth_tx';

const TRANSACTION_TTL_MS = 10 * 60 * 1000;

export interface StartedTransaction {
  transactionId: string;
  state: string;
  codeChallenge: string;
}

export interface ConsumedTransaction {
  codeVerifier: string;
  mode: OAuthMode;
  userId: string | null;
}

@Injectable()
export class OAuthTransactionService {
  constructor(private readonly prisma: PrismaService) {}

  async start(input: {
    provider: OAuthProvider;
    mode?: OAuthMode;
    userId?: string;
  }): Promise<StartedTransaction> {
    const state = randomToken(32);
    const codeVerifier = randomToken(32);

    const row = await this.prisma.oAuthTransaction.create({
      data: {
        stateHash: sha256Hex(state),
        codeVerifier,
        provider: input.provider,
        mode: input.mode ?? OAuthMode.login,
        userId: input.userId,
        expiresAt: new Date(Date.now() + TRANSACTION_TTL_MS),
      },
    });

    return {
      transactionId: row.id,
      state,
      codeChallenge: pkceChallenge(codeVerifier),
    };
  }

  async consume(input: {
    transactionId: string | undefined;
    state: string | undefined;
    provider: OAuthProvider;
  }): Promise<ConsumedTransaction> {
    const { transactionId, state, provider } = input;
    if (!isUuid(transactionId) || !state) {
      throw new AppError('invalid_state', 400);
    }

    const now = new Date();
    // Atomic single use: a replayed, expired or forged callback matches no row.
    const { count } = await this.prisma.oAuthTransaction.updateMany({
      where: {
        id: transactionId,
        stateHash: sha256Hex(state),
        provider,
        consumedAt: null,
        expiresAt: { gt: now },
      },
      data: { consumedAt: now },
    });
    if (count !== 1) {
      throw new AppError('invalid_state', 400);
    }

    const row = await this.prisma.oAuthTransaction.findUniqueOrThrow({
      where: { id: transactionId },
    });
    return {
      codeVerifier: row.codeVerifier,
      mode: row.mode,
      userId: row.userId,
    };
  }
}
