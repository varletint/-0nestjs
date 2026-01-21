import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_ACCESS_SECRET || 'access-secret',
    });
  }

  async validate(payload: { userId: string }) {
    const user = this.authService.findUserById(payload.userId);
    if (!user) {
      throw new UnauthorizedException();
    }
    return { id: user.id, username: user.username, role: user.role };
  }
}
