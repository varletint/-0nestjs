// Simple in-memory user store for demo purposes
// In production, use a real database (TypeORM, Prisma, Mongoose, etc.)

export interface User {
  id: string;
  username: string;
  password: string;
  role: string;
  refreshToken?: string;
}

// In-memory user store (for demo - replace with real DB in production)
export const users: User[] = [];
