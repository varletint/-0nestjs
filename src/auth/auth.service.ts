import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { RegisterDto, LoginDto } from './dto';
import { User, users } from './entities/user.entity';

@Injectable()
export class AuthService {
  constructor(private jwtService: JwtService) {}

  private generateTokens(userId: string) {
    const accessToken = this.jwtService.sign(
      { userId },
      {
        secret: process.env.JWT_ACCESS_SECRET || 'access-secret',
        expiresIn: '15m',
      },
    );

    const refreshToken = this.jwtService.sign(
      { userId },
      {
        secret: process.env.JWT_REFRESH_SECRET || 'refresh-secret',
        expiresIn: '7d',
      },
    );

    return { accessToken, refreshToken };
  }

  async register(registerDto: RegisterDto) {
    const { username, password, role } = registerDto;
    const sanitizedUsername = username.trim().toLowerCase();

    // Check if user exists
    const existingUser = users.find((u) => u.username === sanitizedUsername);
    if (existingUser) {
      throw new ConflictException('Username already taken');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user: User = {
      id: uuidv4(),
      username: sanitizedUsername,
      password: hashedPassword,
      role: role || 'user',
    };

    users.push(user);

    // Generate tokens
    const { accessToken, refreshToken } = this.generateTokens(user.id);

    // Save refresh token
    user.refreshToken = refreshToken;

    return {
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
      accessToken,
      refreshToken,
    };
  }

  async login(loginDto: LoginDto) {
    const { username, password } = loginDto;
    const sanitizedUsername = username.trim().toLowerCase();

    // Find user
    const user = users.find((u) => u.username === sanitizedUsername);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const { accessToken, refreshToken } = this.generateTokens(user.id);

    // Save refresh token
    user.refreshToken = refreshToken;

    return {
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
      accessToken,
      refreshToken,
    };
  }

  async refresh(oldRefreshToken: string) {
    if (!oldRefreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    let decoded: { userId: string };
    try {
      decoded = this.jwtService.verify(oldRefreshToken, {
        secret: process.env.JWT_REFRESH_SECRET || 'refresh-secret',
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Find user and validate refresh token
    const user = users.find((u) => u.id === decoded.userId);
    if (!user || user.refreshToken !== oldRefreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Generate new tokens (rotation)
    const { accessToken, refreshToken } = this.generateTokens(user.id);

    // Update stored refresh token
    user.refreshToken = refreshToken;

    return { accessToken, refreshToken };
  }

  async logout(refreshToken: string) {
    if (refreshToken) {
      const user = users.find((u) => u.refreshToken === refreshToken);
      if (user) {
        user.refreshToken = undefined;
      }
    }
  }

  async getMe(userId: string) {
    const user = users.find((u) => u.id === userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      id: user.id,
      username: user.username,
      role: user.role,
    };
  }

  findUserById(id: string): User | undefined {
    return users.find((u) => u.id === id);
  }
}
