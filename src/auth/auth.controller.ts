import {
  Body,
  Controller,
  Post,
  ValidationPipe,
  UseGuards,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ResetPasswordDto,
  SignInDto,
  SignUpDto,
  VerifyCodeDto,
} from './dto/auth.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LogoutDto } from './dto/logout.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';

@ApiTags('Auth') // Organizes endpoints in Swagger UI
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
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

  @Public()
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

  @Public()
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

  @Public()
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

  @Public()
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

  @Post('refresh-token')
  @ApiOperation({ summary: 'Refresh Access Token' })
  @ApiResponse({
    status: 200,
    description: 'Access token refreshed successfully.',
  })
  refreshToken(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    refreshTokenDto: RefreshTokenDto,
  ) {
    return this.authService.refreshToken(
      refreshTokenDto.refreshToken,
    );
  }

  @Post('logout')
  @ApiOperation({ summary: 'Logout User' })
  @ApiResponse({
    status: 200,
    description: 'User logged out successfully.',
  })
  @ApiBearerAuth('access-token')
  logout(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    logoutDto: LogoutDto,
  ) {
    return this.authService.logout(logoutDto.refreshToken, 1);
  }

  @Post('change-password-secure')
  @ApiOperation({ summary: 'Change Password with Verification' })
  @ApiResponse({
    status: 200,
    description:
      'Password changed successfully with current password verification.',
  })
  changePasswordSecure(
    @Body(new ValidationPipe({ forbidNonWhitelisted: true }))
    changePasswordDto: ChangePasswordDto,
    @CurrentUser() user: any,
  ) {
    return this.authService.changePasswordWithVerification(
      user.id,
      changePasswordDto.currentPassword,
      changePasswordDto.newPassword,
    );
  }
}
