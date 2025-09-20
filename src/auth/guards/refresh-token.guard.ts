import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { CACHE_CONSTANTS, JWT_CONSTANTS } from '../constants';
import { Request } from 'express';

@Injectable()
export class RefreshTokenGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const refreshToken =
      this.extractRefreshTokenFromBody(request) ||
      this.extractTokenFromHeader(request);

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is required');
    }

    try {
      // Check if token is blacklisted
      const isBlacklisted = await this.cacheManager.get(
        `${CACHE_CONSTANTS.BLACKLIST_PREFIX}${refreshToken}`,
      );

      if (isBlacklisted) {
        throw new UnauthorizedException(
          'Refresh token has been revoked',
        );
      }

      // Verify the JWT refresh token
      const payload = await this.jwtService.verifyAsync(
        refreshToken,
        {
          secret: JWT_CONSTANTS.SECRET,
        },
      );

      // Ensure it's a refresh token
      if (payload.type !== 'refresh') {
        throw new UnauthorizedException(
          'Invalid token type - refresh token required',
        );
      }

      // Verify user still exists and is active
      const user = await this.prisma.user.findUnique({
        where: { id: payload.id },
        select: {
          id: true,
          email: true,
          isActive: true,
        },
      });

      if (!user || !user.isActive) {
        throw new UnauthorizedException('User not found or inactive');
      }

      // Add user and refresh token to request object
      request.user = {
        id: user.id,
        email: user.email,
      };
      request.refreshToken = refreshToken;

      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      // JWT verification failed
      throw new UnauthorizedException(
        'Invalid or expired refresh token',
      );
    }
  }

  private extractTokenFromHeader(
    request: Request,
  ): string | undefined {
    const [type, token] =
      request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  private extractRefreshTokenFromBody(
    request: Request,
  ): string | undefined {
    return request.body?.refreshToken;
  }
}
