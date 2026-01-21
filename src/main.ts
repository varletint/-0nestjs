import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Global validation pipe (like express-validator)
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Cookie parser middleware
  app.use(cookieParser());

  // Enable CORS
  app.enableCors({
    origin: 'http://localhost:5173', // Vite dev server
    credentials: true,
  });

  await app.listen(process.env.PORT ?? 3000);
  console.log(
    `🚀 NestJS server running on http://localhost:${process.env.PORT ?? 3000}`,
  );
}
bootstrap();
