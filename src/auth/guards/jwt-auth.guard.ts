import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        email: string;
      };
      refreshToken?: string;
    }
  }
}

/**
 * JWT Authentication Guard
 *
 * This guard protects routes by requiring a valid JWT token.
 * It extends the AuthGuard from @nestjs/passport and uses the 'jwt' strategy.
 *
 * Usage:
 * - Apply this guard to controller methods or classes that require authentication
 * - The guard automatically validates JWT tokens using the JwtStrategy
 * - If validation fails, it throws an UnauthorizedException
 * - If validation succeeds, it attaches the user object to the request
 *
 * Example:
 * @UseGuards(JwtAuthGuard)
 * @Get('profile')
 * getProfile(@CurrentUser() user: User) {
 *   return user;
 * }
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    // 🔑 Check if @Public() is applied
    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (isPublic) {
      return true; // ✅ Skip JWT check
    }
    return super.canActivate(context); // ✅ Enforce JWT otherwise
  }
}
