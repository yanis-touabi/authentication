import {
  ConflictException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import {
  ResetPasswordDto,
  SignInDto,
  SignUpDto,
  VerifyCodeDto,
} from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { MailService } from 'src/mail/mail.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject } from '@nestjs/common';
import { Cache } from 'cache-manager';
import {
  JwtPayload,
  TokenResponse,
} from './interfaces/jwt-payload.interface';
import {
  JWT_CONSTANTS,
  PASSWORD_CONSTANTS,
  VERIFICATION_CONSTANTS,
  CACHE_CONSTANTS,
} from './constants';

/**
 * This service handles all authentication-related operations including:
 * - User registration and login
 * - JWT token generation and management
 * - Password reset and change operations
 * - Email verification
 * - Token blacklisting
 */

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private mailService: MailService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  /**
   * User Registration
   *
   * Creates a new user account with the provided information.
   * Steps:
   * 1. Check if user already exists by email
   * 2. Hash the password using bcrypt
   * 3. Create user in database
   * 4. Generate JWT access token
   * 5. Return user data and token
   */
  async signup(signUpDto: SignUpDto) {
    try {
      // Check if user already exists
      const user = await this.prisma.user.findUnique({
        where: {
          email: signUpDto.email,
        },
      });
      if (user) {
        return new HttpException('User already exist', 400);
      }

      // Hash the password for security
      const password = await bcrypt.hash(
        signUpDto.password,
        PASSWORD_CONSTANTS.SALT_ROUNDS,
      );

      // Prepare user data for creation
      const userCreated = {
        password,
        isActive: true,
      };

      // Create new user in database
      const newUser = await this.prisma.user.create({
        data: {
          ...signUpDto,
          ...userCreated,
        },
      });

      // Create JWT payload (contains user identity information)
      const payload = {
        id: newUser.id,
        email: newUser.email,
      };

      // Generate both access and refresh tokens
      const tokens = await this.generateTokens(payload);

      // Store refresh token hash in cache for validation
      await this.storeRefreshToken(newUser.id, tokens.refreshToken);

      return {
        status: 200,
        message: 'User created successfully',
        data: newUser,
        ...tokens,
      };
    } catch (error) {
      console.error('Error in signup:', {
        email: signUpDto.email,
        error,
      });

      if (error instanceof ConflictException) {
        throw error; // Preserve specific errors
      }

      throw new InternalServerErrorException(
        'An unexpected error occurred during signup',
      );
    }
  }

  /**
   * User Login
   *
   * Authenticates a user and generates JWT tokens.
   * Steps:
   * 1. Find user by email
   * 2. Verify password matches stored hash
   * 3. Remove password from user object for security
   * 4. Generate JWT access token
   * 5. Return user data and token
   */
  async signIn(signInDto: SignInDto) {
    try {
      // Find user by email address
      const user = await this.prisma.user.findUnique({
        where: {
          email: signInDto.email,
        },
      });

      // Check if user exists
      if (!user) {
        return new NotFoundException('User Not Found');
      }

      // Verify password matches stored hash
      const isMatch = await bcrypt.compare(
        signInDto.password,
        user.password,
      );

      // Throw error if password doesn't match
      if (!isMatch) {
        throw new UnauthorizedException();
      }

      // Remove password from user object before returning (security measure)
      delete user.password;

      // Create JWT payload with user identity
      const payload = {
        id: user.id,
        email: user.email,
      };

      // Generate both access and refresh tokens
      const tokens = await this.generateTokens(payload);

      // Store refresh token hash in cache for validation
      await this.storeRefreshToken(user.id, tokens.refreshToken);

      return {
        status: 200,
        message: 'User logged in successfully',
        data: user,
        ...tokens,
      };
    } catch (error) {
      console.error('Error in signIn:', error);
      throw error;
    }
  }

  /**
   * Token Generation Utility
   *
   * Generates both access and refresh tokens for a user.
   * This is a private helper method used by other authentication methods.
   *
   * Access Token: Short-lived token (15 minutes) for API authentication
   * Refresh Token: Long-lived token (7 days) for obtaining new access tokens
   *
   * @param payload JWT payload containing user identity (id, email)
   * @returns Object containing both tokens and expiration information
   */
  private async generateTokens(
    payload: JwtPayload,
  ): Promise<TokenResponse> {
    // Generate access token with short expiration
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: JWT_CONSTANTS.SECRET,
      expiresIn: JWT_CONSTANTS.ACCESS_TOKEN_EXPIRES_IN,
    });

    // Generate refresh token with longer expiration
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: JWT_CONSTANTS.SECRET,
      expiresIn: JWT_CONSTANTS.REFRESH_TOKEN_EXPIRES_IN,
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: 15 * 60, // 15 minutes in seconds (for client-side use)
    };
  }

  /**
   * Store Refresh Token
   *
   * Stores a hash of the refresh token in cache for validation.
   * This allows us to validate refresh tokens and revoke them when needed.
   *
   * @param userId User ID
   * @param refreshToken Refresh token to store
   */
  private async storeRefreshToken(
    userId: number,
    refreshToken: string,
  ) {
    const tokenHash = await bcrypt.hash(refreshToken, 10);
    const cacheKey = `${CACHE_CONSTANTS.REFRESH_TOKEN_PREFIX}${userId}`;

    // Store with TTL matching refresh token expiration (7 days)
    await this.cacheManager.set(
      cacheKey,
      tokenHash,
      7 * 24 * 60 * 60,
    );
  }

  /**
   * Refresh Token
   *
   * Generates a new access token using a valid refresh token.
   * This allows users to maintain their session without re-authenticating.
   *
   * Steps:
   * 1. Verify the refresh token is valid and not expired
   * 2. Check if the refresh token has been blacklisted/revoked
   * 3. Verify the user still exists and is active
   * 4. Generate new access and refresh tokens
   *
   * Security: Refresh tokens are checked against a blacklist to prevent
   * token reuse after logout or revocation.
   *
   * @param refreshToken Valid refresh token obtained during login
   * @returns New access and refresh tokens with success message
   */
  async refreshToken(refreshToken: string) {
    try {
      // Verify the refresh token signature and expiration
      const payload = await this.jwtService.verifyAsync(
        refreshToken,
        {
          secret: JWT_CONSTANTS.SECRET,
        },
      );

      // Check if it's actually a refresh token
      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Check if refresh token has been blacklisted (revoked)
      const isBlacklisted = await this.cacheManager.get(
        `${CACHE_CONSTANTS.BLACKLIST_PREFIX}${refreshToken}`,
      );

      if (isBlacklisted) {
        // disconnect the user from the platform
        throw new UnauthorizedException('Token has been revoked');
      }

      // Validate refresh token against stored hash
      const storedTokenHash = await this.cacheManager.get(
        `${CACHE_CONSTANTS.REFRESH_TOKEN_PREFIX}${payload.id}`,
      );

      if (!storedTokenHash) {
        throw new UnauthorizedException('Refresh token not found');
      }

      const isValidRefreshToken = await bcrypt.compare(
        refreshToken,
        storedTokenHash as string,
      );

      if (!isValidRefreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Get user from database to ensure they still exist and are active
      const user = await this.prisma.user.findUnique({
        where: { id: payload.id },
      });

      if (!user || !user.isActive) {
        throw new UnauthorizedException('User not found or inactive');
      }

      // Generate new access and refresh tokens
      const newPayload = { id: user.id, email: user.email };
      const tokens = await this.generateTokens(newPayload);

      // Blacklist the old refresh token
      await this.blacklistToken(refreshToken);

      // Store new refresh token
      await this.storeRefreshToken(user.id, tokens.refreshToken);

      return {
        status: 200,
        message: 'Token refreshed successfully',
        ...tokens,
      };
    } catch (error) {
      console.error('Error in refreshToken:', error);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * User Logout
   *
   * Securely logs out a user by blacklisting their refresh token.
   * This prevents the refresh token from being used to obtain new access tokens.
   *
   * Steps:
   * 1. Verify the refresh token to get its expiration time
   * 2. Calculate remaining time until token expiration
   * 3. Add token to Redis blacklist with TTL equal to remaining time
   *
   * Security: The token is blacklisted only for its remaining validity period
   * to avoid unnecessary storage of expired tokens.
   *
   * @param refreshToken Refresh token to be blacklisted
   * @returns Success message confirming logout
   */
  async logout(refreshToken: string, userId?: number) {
    try {
      let userIdToLogout = userId;

      //! review this and fix it !!
      // If userId not provided, extract it from the token
      if (!userIdToLogout) {
        const payload = await this.jwtService.verifyAsync(
          refreshToken,
          {
            secret: JWT_CONSTANTS.SECRET,
          },
        );
        userIdToLogout = payload.id;
      }

      // Blacklist the refresh token
      await this.blacklistToken(refreshToken);

      // Remove refresh token from cache
      await this.cacheManager.del(
        `${CACHE_CONSTANTS.REFRESH_TOKEN_PREFIX}${userIdToLogout}`,
      );

      return {
        status: 200,
        message: 'Logged out successfully',
      };
    } catch (error) {
      console.error('Error in logout:', error);
      // Don't throw error for invalid tokens during logout
      return {
        status: 200,
        message: 'Logged out successfully',
      };
    }
  }

  /**
   * Logout from all devices
   *
   * Invalidates all refresh tokens for a user across all devices.
   *
   * @param userId User ID
   * @returns Success message
   */
  // async logoutFromAllDevices(userId: number) {
  //   try {
  //     // Remove all refresh tokens for the user
  //     await this.cacheManager.del(
  //       `${CACHE_CONSTANTS.REFRESH_TOKEN_PREFIX}${userId}`,
  //     );

  //     // You might also want to blacklist all existing tokens for this user
  //     // This would require storing token IDs or implementing a user-based blacklist

  //     return {
  //       status: 200,
  //       message: 'Logged out from all devices successfully',
  //     };
  //   } catch (error) {
  //     console.error('Error in logoutFromAllDevices:', error);
  //     throw new InternalServerErrorException(
  //       'Error occurred while logging out from all devices',
  //     );
  //   }
  // }

  /**
   * Blacklist Token
   *
   * Adds a token to the blacklist to prevent its future use.
   *
   * @param token Token to blacklist
   */
  private async blacklistToken(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: JWT_CONSTANTS.SECRET,
      });

      const currentTime = Math.floor(Date.now() / 1000);
      const timeUntilExpiry = payload.exp - currentTime;

      if (timeUntilExpiry > 0) {
        await this.cacheManager.set(
          `${CACHE_CONSTANTS.BLACKLIST_PREFIX}${token}`,
          'revoked',
          timeUntilExpiry,
        );
      }
    } catch (error) {
      // Token might be invalid or expired, which is fine
      console.log('Token already invalid or expired:', error.message);
    }
  }

  /**
   * Password Reset Request
   *
   * Initiates the password reset process by:
   * 1. Finding the user by email
   * 2. Generating a 6-digit verification code
   * 3. Storing the code in the database
   * 4. Sending the code via email
   *
   * This is the first step in the password reset flow.
   * The user must then verify the code before changing their password.
   *
   * @param email User's email address for password reset
   * @returns Success message or error if user not found
   */
  async resetPassword({ email }: ResetPasswordDto) {
    try {
      // Find user by email address
      const user = await this.prisma.user.findUnique({
        where: { email },
      });

      // Return error if user doesn't exist
      if (!user) {
        return new NotFoundException('User Not Found');
      }

      // Generate secure 6-digit verification code
      const code = Math.floor(Math.random() * 1000000)
        .toString()
        .padStart(6, '0');

      // Store verification code in database for later validation
      await this.prisma.user.update({
        where: { email },
        data: { verificationCode: code },
      });

      // Send password reset email with verification code
      await this.mailService.sendResetPasswordEmail(
        email,
        code,
        `${user.firstName} ${user.lastName}`,
      );

      return {
        status: 200,
        message: `Code sent successfully to your email (${email})`,
      };
    } catch (error) {
      console.error('Error in resetPassword:', error);

      if (error instanceof NotFoundException) {
        throw error; // Rethrow specific known errors
      }

      throw new InternalServerErrorException(
        'Something went wrong while processing your request',
      );
    }
  }

  /**
   * Verification Code Validation
   *
   * Validates a verification code sent to the user's email.
   * This is the second step in the password reset process.
   *
   * Steps:
   * 1. Find user by email and retrieve stored verification code
   * 2. Compare provided code with stored code
   * 3. Clear the verification code after successful validation
   * 4. Return success message to proceed with password change
   *
   * @param email User's email address
   * @param code 6-digit verification code sent to the user
   * @returns Success message or validation error
   */
  async verifyCode({ email, code }: { email: string; code: string }) {
    try {
      // Find user and retrieve only the verification code field
      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
        select: {
          verificationCode: true,
        },
      });

      // Return error if user doesn't exist
      if (!user) {
        return new NotFoundException('User Not Found');
      }

      // Validate that the provided code matches the stored code
      if (user.verificationCode !== code) {
        return new UnauthorizedException('Invalid code');
      }

      // Clear the verification code after successful validation
      // This prevents code reuse and enhances security
      await this.prisma.user.update({
        where: {
          email,
        },
        data: {
          verificationCode: null,
        },
      });

      return {
        status: 200,
        message:
          'Code verified successfully, proceed to change your password',
      };
    } catch (error) {
      console.error('Error in verifyCode:', error);
      if (
        error instanceof NotFoundException ||
        error instanceof UnauthorizedException
      ) {
        throw error; // Preserve known exceptions
      }

      throw new InternalServerErrorException(
        'An unexpected error occurred during verification',
      );
    }
  }

  /**
   * Password Change (Without Current Password Verification)
   *
   * Changes a user's password without requiring the current password.
   * This is typically used after email verification in the password reset flow.
   *
   * Steps:
   * 1. Find user by email
   * 2. Hash the new password
   * 3. Update the user's password in the database
   * 4. Return success message
   *
   * Note: This method does NOT verify the current password, making it suitable
   * for password reset scenarios where the user has already been authenticated
   * via email verification.
   *
   * @param changePasswordData Contains email and new password
   * @returns Success message or error if user not found
   */
  async changePassword(changePasswordData: SignInDto) {
    try {
      // Find user by email address
      const user = await this.prisma.user.findUnique({
        where: {
          email: changePasswordData.email,
        },
      });

      // Return error if user doesn't exist
      if (!user) {
        return new NotFoundException('User Not Found');
      }

      // Hash the new password for secure storage
      const password = await bcrypt.hash(
        changePasswordData.password,
        PASSWORD_CONSTANTS.SALT_ROUNDS,
      );

      // Update user's password in the database
      await this.prisma.user.update({
        where: {
          email: changePasswordData.email,
        },
        data: {
          password,
        },
      });

      return {
        status: 200,
        message: 'Password changed successfully, go to login',
      };
    } catch (error) {
      console.error('Error in changePassword:', {
        email: changePasswordData.email,
        error,
      });

      if (error instanceof NotFoundException) {
        throw error; // Preserve known exceptions
      }

      throw new InternalServerErrorException(
        'An unexpected error occurred while changing the password',
      );
    }
  }

  // Change password with current password verification
  async changePasswordWithVerification(
    userId: number,
    currentPassword: string,
    newPassword: string,
  ) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Verify current password
      const isCurrentPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password,
      );

      if (!isCurrentPasswordValid) {
        throw new UnauthorizedException(
          'Current password is incorrect',
        );
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(
        newPassword,
        PASSWORD_CONSTANTS.SALT_ROUNDS,
      );

      // Update password
      await this.prisma.user.update({
        where: { id: userId },
        data: { password: hashedPassword },
      });

      return {
        status: 200,
        message: 'Password changed successfully',
      };
    } catch (error) {
      console.error(
        'Error in changePasswordWithVerification:',
        error,
      );
      throw error;
    }
  }
}
