import {
  ConflictException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import {
  ResetPasswordDto,
  SignInDto,
  SignUpDto,
} from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { MailService } from 'src/mail/mail.service';
import {
  JwtPayload,
  TokenResponse,
} from './interfaces/jwt-payload.interface';
import { JWT_CONSTANTS, PASSWORD_CONSTANTS } from './constants';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}

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
        throw new UnauthorizedException('Invalid credentials');
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

  private async storeRefreshToken(
    userId: number,
    refreshToken: string,
  ) {
    try {
      const tokenHash = await bcrypt.hash(refreshToken, 10);

      // Calculate expiration date (7 days from now)
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      // Store the token in database (allow multiple tokens per user)
      await this.prisma.token.create({
        data: {
          userId: userId,
          refreshToken: tokenHash,
          expiresAt: expiresAt,
        },
      });

      // Optional: Verify the token was stored
      const storedToken = await this.prisma.token.findFirst({
        where: {
          userId: userId,
          refreshToken: tokenHash,
        },
      });

      if (!storedToken) {
        throw new Error('Failed to store refresh token in database');
      }

      return storedToken;
    } catch (error) {
      console.error('❌ Error in storeRefreshToken:', error);
      throw error;
    }
  }

  // Remove all tokens for a user (for complete logout)
  private async removeAllUserTokens(userId: number) {
    return this.prisma.token.deleteMany({
      where: {
        userId: userId,
      },
    });
  }

  //! a modifier apres
  // Remove expired tokens (cleanup function)
  private async cleanupExpiredTokens() {
    return this.prisma.token.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(), // Delete expired tokens
        },
      },
    });
  }

  // Verify a specific refresh token
  private async verifyRefreshToken(
    userId: number,
    refreshToken: string,
  ) {
    const tokens = await this.prisma.token.findMany({
      where: {
        userId: userId,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    for (const token of tokens) {
      const isValid = await bcrypt.compare(
        refreshToken,
        token.refreshToken,
      );
      if (isValid) {
        return token; // Return the valid token
      }
    }

    return null; // No valid token found
  }

  async refreshToken(refreshToken: string, deviceId?: string) {
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

      // Get user from database to ensure they still exist and are active
      const user = await this.prisma.user.findUnique({
        where: { id: payload.id },
      });

      if (!user || !user.isActive) {
        throw new UnauthorizedException('User not found or inactive');
      }

      // Get all active refresh tokens for this user from database
      const activeTokens = await this.prisma.token.findMany({
        where: {
          userId: user.id,
          expiresAt: {
            gt: new Date(), // Only non-expired tokens
          },
        },
      });

      // Check if the provided refresh token matches any stored token
      let isValidRefreshToken = false;
      let matchingToken = null;

      for (const token of activeTokens) {
        const isMatch = await bcrypt.compare(
          refreshToken,
          token.refreshToken,
        );
        if (isMatch) {
          isValidRefreshToken = true;
          matchingToken = token;
          break;
        }
      }

      if (!isValidRefreshToken || !matchingToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Check if the token has been blacklisted (optional - if you still want blacklisting)
      // const isBlacklisted = await this.prisma.blacklistedToken.findUnique({
      //   where: { tokenHash: await bcrypt.hash(refreshToken, 10) },
      // });
      // if (isBlacklisted) {
      //   throw new UnauthorizedException('Token has been revoked');
      // }

      // Generate new access and refresh tokens
      const newPayload = { id: user.id, email: user.email };
      const tokens = await this.generateTokens(newPayload);

      // Remove the old refresh token from database
      await this.prisma.token.delete({
        where: { id: matchingToken.id },
      });

      // Store new refresh token (with device info if available)
      await this.storeRefreshToken(user.id, tokens.refreshToken);

      return {
        status: 200,
        message: 'Token refreshed successfully',
        ...tokens,
      };
    } catch (error) {
      console.error('Error in refreshToken:', error);

      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(refreshToken: string, userId?: number) {
    try {
      let userIdToLogout = userId;

      // If userId not provided, try to extract it from the token
      if (!userIdToLogout) {
        try {
          const payload = await this.jwtService.verifyAsync(
            refreshToken,
            {
              secret: JWT_CONSTANTS.SECRET,
            },
          );
          userIdToLogout = payload.id;
        } catch (jwtError) {
          // If token is invalid but we have no userId, still return success
          if (!userIdToLogout) {
            console.warn(
              'Invalid token and no userId provided, proceeding with logout',
            );
            return {
              status: 200,
              message: 'Logged out successfully',
            };
          }
        }
      }

      if (userIdToLogout && refreshToken) {
        // Find and remove the specific refresh token from database
        const userTokens = await this.prisma.token.findMany({
          where: {
            userId: userIdToLogout,
          },
        });

        // Find the specific token to delete
        for (const token of userTokens) {
          try {
            const isValid = await bcrypt.compare(
              refreshToken,
              token.refreshToken,
            );
            if (isValid) {
              await this.prisma.token.delete({
                where: { id: token.id },
              });
              console.log(
                `Removed refresh token for user ${userIdToLogout}`,
              );
              break;
            }
          } catch (compareError) {
            console.warn('Error comparing token hash:', compareError);
            // Continue checking other tokens
          }
        }

        // Optional: Blacklist the refresh token
        // await this.blacklistToken(refreshToken);
      } else if (userIdToLogout) {
        // If only userId provided, remove all tokens for the user (full logout)
        await this.prisma.token.deleteMany({
          where: {
            userId: userIdToLogout,
          },
        });
        console.log(`Removed all tokens for user ${userIdToLogout}`);
      }

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
  async logoutFromAllDevices(userId: number) {
    try {
      // Remove all refresh tokens for the user from database
      await this.prisma.token.deleteMany({
        where: {
          userId: userId,
        },
      });

      return {
        status: 200,
        message: 'Logged out from all devices successfully',
      };
    } catch (error) {
      console.error('Error in logoutFromAllDevices:', error);
      throw new InternalServerErrorException(
        'Error occurred while logging out from all devices',
      );
    }
  }

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
      console.log('user id', userId);
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
