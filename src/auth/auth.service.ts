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
// import { Role } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { MailService } from 'src/mail/mail.service';
const saltOrRounds = 10;

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}

  async signup(signUpDto: SignUpDto) {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          email: signUpDto.email,
        },
      });
      if (user) {
        return new HttpException('User already exist', 400);
      }
      const password = await bcrypt.hash(
        signUpDto.password,
        saltOrRounds,
      );
      const userCreated = {
        password,
        isActive: true,
      };
      const newUser = await this.prisma.user.create({
        data: {
          ...signUpDto,
          ...userCreated,
        },
      });

      const payload = {
        id: newUser.id,
        email: newUser.email,
      };

      const token = await this.jwtService.signAsync(payload, {
        secret: process.env.JWT_SECRET,
      });

      return {
        status: 200,
        message: 'User created successfully',
        data: newUser,
        access_token: token,
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
      // email, password
      const user = await this.prisma.user.findUnique({
        where: {
          email: signInDto.email,
        },
      });

      if (!user) {
        return new NotFoundException('User Not Found');
      }

      const isMatch = await bcrypt.compare(
        signInDto.password,
        user.password,
      );

      if (!isMatch) {
        throw new UnauthorizedException();
      }

      delete user.password;

      const payload = {
        id: user.id,
        email: user.email,
      };

      const token = await this.jwtService.signAsync(payload, {
        secret: process.env.JWT_SECRET,
      });

      return {
        status: 200,
        message: 'User logged in successfully',
        data: user,
        access_token: token,
      };
    } catch (error) {
      console.error('Error in signIn:', error);
      throw error;
    }
  }

  async resetPassword({ email }: ResetPasswordDto) {
    try {
      // Find user by email
      const user = await this.prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return new NotFoundException('User Not Found');
      }

      // Generate 6-digit verification code
      const code = Math.floor(Math.random() * 1000000)
        .toString()
        .padStart(6, '0');

      // Update the verificationCode field in the database
      await this.prisma.user.update({
        where: { email },
        data: { verificationCode: code },
      });

      // Send reset password email
      await this.mailService.sendResetPasswordEmail(
        email,
        'Réinitialisation de votre mot de passe',
        'reset-password',
        code,
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
      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
        select: {
          verificationCode: true,
        },
      });

      if (!user) {
        return new NotFoundException('User Not Found');
      }

      if (user.verificationCode !== code) {
        return new UnauthorizedException('Invalid code');
      }

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
      const user = await this.prisma.user.findUnique({
        where: {
          email: changePasswordData.email,
        },
      });

      if (!user) {
        return new NotFoundException('User Not Found');
      }

      const password = await bcrypt.hash(
        changePasswordData.password,
        saltOrRounds,
      );

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
}
