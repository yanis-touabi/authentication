import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as express from 'express';
import * as path from 'path';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // ✅ Enable CORS for all origins
  app.enableCors({
    origin: '*', // Allow all origins
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  // Swagger Configuration
  const config = new DocumentBuilder()
    .setTitle('API Documentation')
    .setDescription('NestJS API with Swagger')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        in: 'header',
      },
      'BearerAuth', // Use consistent name for security scheme
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);

  // 🔹 Apply BearerAuth globally to all routes
  document.security = [{ BearerAuth: [] }]; // Global security

  SwaggerModule.setup('api-docs', app, document);

  // Serve static files from "public" folder
  //! this is for deployment
  // app.use(
  //   '/images',
  //   express.static(path.join(__dirname, '..', 'public')),
  // );

  //! this is for developement
  app.use(
    '/images',
    express.static(path.join(process.cwd(), 'public', 'images')),
  );

  await app.listen(process.env.PORT || 4000);
}
bootstrap();
