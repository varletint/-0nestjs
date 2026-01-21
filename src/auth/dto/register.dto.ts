import { IsString, MinLength, Matches, IsOptional } from 'class-validator';

export class RegisterDto {
  @IsString()
  @MinLength(3)
  @Matches(/^[a-zA-Z0-9_]{3,30}$/, {
    message:
      'Username must be 3-30 characters and can only contain letters, numbers, and underscores',
  })
  username: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/, {
    message:
      'Password must be at least 8 characters with 1 uppercase, 1 lowercase, and 1 number',
  })
  password: string;

  @IsOptional()
  @IsString()
  role?: string;
}
