import {
  Body,
  Controller,
  Post,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ResetPasswordDto,
  SignInDto,
  SignUpDto,
  VerifyCodeDto,
} from './dto/auth.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Auth') // Organizes endpoints in Swagger UI
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  @ApiOperation({ summary: 'Sign Up' })
  @ApiResponse({
    status: 200,
    description: 'User successfully signed up.',
  })
  signUp(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    signUpDto: SignUpDto,
  ) {
    return this.authService.signup(signUpDto);
  }

  @Post('sign-in')
  @ApiOperation({ summary: 'Sign In' })
  @ApiResponse({
    status: 200,
    description: 'User successfully signed in.',
  })
  signIn(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    signInDto: SignInDto,
  ) {
    return this.authService.signIn(signInDto);
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Reset Password' })
  @ApiResponse({
    status: 200,
    description: 'Password reset email sent.',
  })
  resetPassword(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    email: ResetPasswordDto,
  ) {
    return this.authService.resetPassword(email);
  }

  @Post('verify-code')
  @ApiOperation({ summary: 'Verify Code' })
  @ApiResponse({
    status: 200,
    description:
      'Code successfully verified. Returns user information.',
  })
  verifyCode(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    verifyCode: VerifyCodeDto,
  ) {
    return this.authService.verifyCode(verifyCode);
  }

  @Post('change-password')
  @ApiOperation({ summary: 'Change Password' })
  @ApiResponse({
    status: 200,
    description: 'Password successfully changed.',
  })
  changePassword(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    changePasswordData: SignInDto,
  ) {
    return this.authService.changePassword(changePasswordData);
  }
}
