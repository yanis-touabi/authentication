import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import {
  EmailOptions,
  EmailTemplateContext,
} from './interfaces/email-options.interface';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  private async sendEmail(options: EmailOptions): Promise<boolean> {
    try {
      await this.mailerService.sendMail({
        from: `Authentication System <${process.env.EMAIL_USERNAME}>`,
        to: options.to,
        subject: options.subject,
        template: options.template,
        context: options.context,
      });

      console.log(`Email sent successfully to ${options.to}`);
      return true;
    } catch (error) {
      console.error('Error sending email:', error);
      return false;
    }
  }

  async sendResetPasswordEmail(
    to: string,
    code: string,
    name?: string,
  ): Promise<boolean> {
    return this.sendEmail({
      to,
      subject: 'Password Reset Request',
      template: 'reset-password',
      context: {
        name: name || 'User',
        code,
        expiration: '15 minutes',
      },
    });
  }

  async sendWelcomeEmail(to: string, name: string): Promise<boolean> {
    return this.sendEmail({
      to,
      subject: 'Welcome to Our Platform!',
      template: 'welcome',
      context: {
        name,
      },
    });
  }

  async sendVerificationEmail(
    to: string,
    code: string,
    name?: string,
  ): Promise<boolean> {
    return this.sendEmail({
      to,
      subject: 'Verify Your Email Address',
      template: 'verification',
      context: {
        name: name || 'User',
        code,
        expiration: '15 minutes',
      },
    });
  }

  async sendPasswordChangedEmail(
    to: string,
    name?: string,
  ): Promise<boolean> {
    return this.sendEmail({
      to,
      subject: 'Password Changed Successfully',
      template: 'password-changed',
      context: {
        name: name || 'User',
      },
    });
  }

  async sendCustomEmail(
    to: string,
    subject: string,
    template: string,
    context: EmailTemplateContext,
  ): Promise<boolean> {
    return this.sendEmail({
      to,
      subject,
      template,
      context,
    });
  }
}
