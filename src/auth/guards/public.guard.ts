import {
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

/**
 * Public Guard
 *
 * This guard allows bypassing authentication for routes marked with @Public().
 * It works in conjunction with the JwtAuthGuard to create a flexible authentication system.
 *
 * How it works:
 * - Checks if a route or controller is decorated with @Public()
 * - If marked as public, allows the request to proceed without authentication
 * - If not marked as public, allows other guards (like JwtAuthGuard) to handle authentication
 *
 * Usage:
 * This guard is automatically applied globally in AuthModule to work with JwtAuthGuard
 *
 * Example:
 * @Public()
 * @Get('public-route')
 * getPublicData() {
 *   return { message: 'This route is publicly accessible' };
 * }
 */
@Injectable()
export class PublicGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  /**
   * Determine if the route can be activated without authentication
   *
   * This method checks if the route or controller is decorated with @Public()
   * using NestJS's Reflector to read metadata.
   *
   * @param context Execution context containing request information
   * @returns Boolean indicating whether the route is public
   */
  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC_KEY,
      [context.getHandler(), context.getClass()],
    );

    return isPublic;
  }
}
