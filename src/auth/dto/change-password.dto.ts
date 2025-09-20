import { IsNotEmpty, IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordDto {
  @ApiProperty({
    example: 'currentPassword123',
    description: 'User current password',
  })
  @IsNotEmpty({ message: 'Current password is required' })
  @IsString({ message: 'Current password must be a string' })
  @MinLength(6, { message: 'Current password must be at least 6 characters' })
  currentPassword: string;

  @ApiProperty({
    example: 'newSecurePassword123',
    description: 'User new password',
  })
  @IsNotEmpty({ message: 'New password is required' })
  @IsString({ message: 'New password must be a string' })
  @MinLength(8, { message: 'New password must be at least 8 characters' })
  @MaxLength(30, { message: 'New password must be at most 30 characters' })
  newPassword: string;

  @ApiProperty({
    example: 'newSecurePassword123',
    description: 'Confirmation of new password',
  })
  @IsNotEmpty({ message: 'Password confirmation is required' })
  @IsString({ message: 'Password confirmation must be a string' })
  confirmNewPassword: string;
}
