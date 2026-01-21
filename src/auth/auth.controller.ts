import {
  Controller,
  Post,
  Body,
  Get,
  Res,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from './dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(
    @Body() registerDto: RegisterDto,
    @Res() res: Response,
  ): Promise<Response> {
    const { user, accessToken, refreshToken } =
      await this.authService.register(registerDto);

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    return res.status(HttpStatus.CREATED).json({
      success: true,
      message: 'User registered successfully',
      data: { user, accessToken },
    });
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res() res: Response,
  ): Promise<Response> {
    const { user, accessToken, refreshToken } =
      await this.authService.login(loginDto);

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    return res.json({
      success: true,
      message: 'User logged in successfully',
      data: { user, accessToken },
    });
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request, @Res() res: Response): Promise<Response> {
    const oldRefreshToken = req.cookies?.refreshToken;
    const { accessToken, refreshToken } =
      await this.authService.refresh(oldRefreshToken);

    // Set new refresh token (token rotation)
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: { accessToken },
    });
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res() res: Response): Promise<Response> {
    const refreshToken = req.cookies?.refreshToken;
    await this.authService.logout(refreshToken);

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return res.json({
      success: true,
      message: 'Logged out successfully',
    });
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getMe(@Req() req: Request) {
    const user = req.user as { id: string };
    const userData = await this.authService.getMe(user.id);
    return {
      success: true,
      message: 'User fetched successfully',
      user: userData,
    };
  }
}
