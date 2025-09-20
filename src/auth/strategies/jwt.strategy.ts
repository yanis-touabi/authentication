import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

/**
 * JWT Strategy
 *
 * This strategy handles JWT token validation and user authentication.
 * It extends Passport's Strategy class to provide JWT authentication.
 *
 * Responsibilities:
 * - Extract JWT token from Authorization header
 * - Validate token signature and expiration
 * - Verify user exists and is active in database
 * - Attach user object to request for use in controllers
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private prisma: PrismaService) {
    super({
      // Extract JWT token from Authorization header as Bearer token
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),

      // Don't ignore expiration - tokens must be valid
      ignoreExpiration: false,

      // Use the same secret key that was used to sign the tokens
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  /**
   * Validate Method
   *
   * This method is called after the JWT token is successfully verified.
   * It validates that the user still exists in the database and is active.
   *
   * Steps:
   * 1. Extract user ID from JWT payload
   * 2. Find user in database (excluding sensitive fields like password)
   * 3. Check if user exists and is active
   * 4. Return user object to be attached to the request
   *
   * @param payload Decoded JWT payload containing user information
   * @returns User object without sensitive data
   * @throws UnauthorizedException if user not found or inactive
   */
  async validate(payload: JwtPayload) {
    // Find user in database, excluding sensitive information
    const user = await this.prisma.user.findUnique({
      where: { id: payload.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        isActive: true,
        // role: true, // Uncomment when role-based auth is implemented
      },
    });

    console.log('user', user);

    // Check if user exists and account is active
    if (!user || !user.isActive) {
      console.log('rani hna', user);
      throw new UnauthorizedException('User not found or inactive');
    }

    console.log('hello world');
    // The returned user object will be attached to the request as req.user
    return user;
  }
}
