import {
  IsEmail,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SignUpDto {
  // firstName
  @ApiProperty({
    example: 'Yanis',
    description: 'User first name',
  })
  @IsString({ message: 'firstName must be a string' })
  @MinLength(3, {
    message: 'firstName must be at least 3 characters',
  })
  @MaxLength(30, {
    message: 'firstName must be at most 30 characters',
  })
  firstName: string;
  // lastName
  @ApiProperty({
    example: 'Touabi',
    description: 'User last name',
  })
  @IsString({ message: 'lastName must be a string' })
  @MinLength(3, { message: 'lastName must be at least 3 characters' })
  @MaxLength(30, {
    message: 'lastName must be at most 30 characters',
  })
  lastName: string;
  // Email
  @ApiProperty({
    example: 'yanis.touabi@gmail.com',
    description: 'User email',
  })
  @IsString({ message: 'Email must be a string' })
  @MinLength(0, { message: 'Thie Email Must be Required' })
  @IsEmail({}, { message: 'Email is not valid' })
  email: string;
  // Password
  @ApiProperty({
    example: '123456',
    description: 'User password',
  })
  @IsString({ message: 'Password must be a string' })
  @MinLength(3, { message: 'password must be at least 3 characters' })
  @MaxLength(20, {
    message: 'password must be at most 20 characters',
  })
  password: string;
}
export class SignInDto {
  // Email
  @ApiProperty({
    example: 'yanis.touabi@gmail.com',
    description: 'User email',
  })
  @IsString({ message: 'Email must be a string' })
  @MinLength(0, { message: 'Thie Email Must be Required' })
  @IsEmail({}, { message: 'Email is not valid' })
  email: string;
  // Password
  @ApiProperty({
    example: '123456',
    description: 'User password',
  })
  @IsString({ message: 'Password must be a string' })
  @MinLength(3, { message: 'password must be at least 3 characters' })
  @MaxLength(20, {
    message: 'password must be at most 20 characters',
  })
  password: string;
}
export class ResetPasswordDto {
  // Email
  @ApiProperty({
    example: 'yanis.touabi@gmail.com',
    description: 'User email',
  })
  @IsString({ message: 'Email must be a string' })
  @MinLength(0, { message: 'Thie Email Must be Required' })
  @IsEmail({}, { message: 'Email is not valid' })
  email: string;
}
export class VerifyCodeDto {
  @ApiProperty({
    example: 'yanis.touabi@gmail.com',
    description: 'User email',
  })
  @IsString({ message: 'Email must be a string' })
  @MinLength(0, { message: 'Thie Email Must be Required' })
  @IsEmail({}, { message: 'Email is not valid' })
  email: string;

  @ApiProperty({
    example: '123456',
    description: 'Verification code',
  })
  @IsString({ message: 'Code must be a string' })
  @MinLength(6, { message: 'Code must be at least 6 characters' })
  @MaxLength(6, { message: 'Code must be at most 6 characters' })
  code: string;
}
