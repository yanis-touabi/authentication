# Complete Authentication System - NestJS

A comprehensive authentication system built with NestJS, featuring JWT tokens, refresh tokens, email verification, password management, and secure session handling.

## 🚀 Features

### Core Authentication

- **Sign Up** - User registration with email verification
- **Sign In** - User login with JWT token generation
- **JWT Authentication** - Secure token-based authentication
- **Refresh Tokens** - Automatic token refresh mechanism
- **Logout** - Secure token revocation and session management

### Password Management

- **Forgot Password** - Password reset via email
- **Reset Password** - Secure password reset with verification codes
- **Change Password** - Password change with current password verification
- **Password Strength** - Enhanced password validation

### Email System

- **Welcome Emails** - New user onboarding
- **Verification Emails** - Email address verification
- **Password Reset Emails** - Secure password reset flow
- **Password Changed Notification** - Security notifications

### Security Features

- **Token Blacklisting** - Redis-based token revocation
- **Rate Limiting** - Protection against brute force attacks
- **Input Validation** - Comprehensive DTO validation
- **Role-based Access** - Flexible authorization system
- **CORS Protection** - Cross-origin resource sharing security

## 📁 Project Structure

```
src/
├── auth/                           # Core Authentication Module
│   ├── dto/                        # Data Transfer Objects
│   ├── guards/                     # Authentication Guards
│   ├── strategies/                 # Passport Strategies
│   ├── decorators/                 # Custom Decorators
│   ├── interfaces/                 # TypeScript Interfaces
│   └── constants.ts                # Configuration Constants
│
├── mail/                           # Email Module
│   ├── templates/                  # Email Templates (Handlebars)
│   ├── interfaces/                 # Email Interfaces
│   └── mail.service.ts             # Email Service
│
├── prisma/                         # Database Module
│   ├── prisma.service.ts           # Prisma Service
│   └── prisma.module.ts            # Prisma Module
│
└── app.module.ts                   # Root Module
```

## 🛠️ Installation & Setup

1. **Install Dependencies**

   ```bash
   npm install
   # or
   yarn install
   ```

2. **Environment Configuration**

   ```bash
   cp .env.example .env
   # Edit .env with your actual configuration
   ```

3. **Database Setup**

   ```bash
   npx prisma generate
   npx prisma db push
   # or for migrations
   npx prisma migrate dev
   ```

4. **Start the Application**
   ```bash
   npm run start:dev
   # or
   yarn start:dev
   ```

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/dbname"

# JWT
JWT_SECRET="your-super-secret-key"
JWT_ACCESS_EXPIRES_IN="15m"
JWT_REFRESH_EXPIRES_IN="7d"

# Email (Gmail example)
EMAIL_USERNAME="your-email@gmail.com"
EMAIL_PASSWORD="your-app-password"

# Redis
REDIS_HOST="localhost"
REDIS_PORT=6379

# Application
PORT=3000
NODE_ENV="development"
```

### Prisma Schema

The system uses Prisma with the following models:

- **User** - User accounts and profiles
- **Token** - Refresh token management
- **Address** - User address information

## 📋 API Endpoints

### Authentication Endpoints

| Method | Endpoint                       | Description            | Authentication |
| ------ | ------------------------------ | ---------------------- | -------------- |
| POST   | `/auth/sign-up`                | User registration      | Public         |
| POST   | `/auth/sign-in`                | User login             | Public         |
| POST   | `/auth/refresh-token`          | Refresh access token   | Public         |
| POST   | `/auth/logout`                 | User logout            | JWT Required   |
| POST   | `/auth/reset-password`         | Request password reset | Public         |
| POST   | `/auth/verify-code`            | Verify reset code      | Public         |
| POST   | `/auth/change-password`        | Change password        | Public         |
| POST   | `/auth/change-password-secure` | Secure password change | JWT Required   |

## 🔐 Security Features

### JWT Token Management

- Access tokens expire in 15 minutes
- Refresh tokens expire in 7 days
- Automatic token refresh mechanism
- Redis-based token blacklisting

### Password Security

- BCrypt password hashing (10 rounds)
- Minimum password length: 8 characters
- Maximum password length: 30 characters
- Current password verification for changes

### Rate Limiting

- Built-in rate limiting protection
- Configurable request limits
- IP-based throttling

### Input Validation

- Class-validator DTO validation
- Custom validation pipes
- SQL injection protection
- XSS protection

## 📧 Email Templates

The system includes four email templates:

1. **Welcome Email** - Sent after successful registration
2. **Verification Email** - Email address verification
3. **Reset Password Email** - Password reset instructions
4. **Password Changed Notification** - Security confirmation

Templates are built with Handlebars and include responsive HTML design.

## 🧪 Testing

Run the test suite:

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

## 🚀 Deployment

### Production Build

```bash
npm run build
npm run start:prod
```

### Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist/ ./dist/
EXPOSE 3000
CMD ["node", "dist/main"]
```

## 📝 License

This project is licensed under the UNLICENSED license.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 🆘 Support

For support and questions:

- Create an issue in the repository
- Contact the development team
- Check the documentation

---

**Note**: This authentication system is production-ready and includes comprehensive security features. Always ensure proper environment configuration and regular security audits.
