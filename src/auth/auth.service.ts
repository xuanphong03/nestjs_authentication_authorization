import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/db/prisma.service';
import Hash from 'src/utils/hashing';
import { LoginAuthDto } from './dto/login-auth.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { redis } from 'src/utils/redis';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  async createAccessToken(userId: number, email: string) {
    const accessToken = await this.jwt.signAsync(
      { userId, email },
      {
        secret: process.env.JWT_AT_SECRET,
        expiresIn: process.env.JWT_AT_EXPIRE,
      },
    );
    return accessToken;
  }

  async createRefreshToken(userId: number, email: string) {
    const refreshToken = await this.jwt.signAsync(
      { userId, email },
      {
        secret: process.env.JWT_RT_SECRET,
        expiresIn: process.env.JWT_RT_EXPIRE,
      },
    );
    return refreshToken;
  }

  async register(body: RegisterAuthDto) {
    body.role = 'user';
    body.password = Hash.make(body.password);
    const user = await this.prisma.user.create({ data: body });
    const accessToken = await this.createAccessToken(user.id, user.email);
    const refreshToken = await this.createRefreshToken(user.id, user.email);
    return { accessToken, refreshToken, user };
  }

  async login({ email, password }: LoginAuthDto) {
    const user = await this.findUserByField('email', email);
    if (!user) {
      return false;
    }
    const hashPassword = user.password;
    if (!Hash.verify(password, hashPassword)) {
      return false;
    }
    const accessToken = await this.createAccessToken(user.id, user.email);
    const refreshToken = await this.createRefreshToken(user.id, user.email);

    //Lưu refresh token vào redis
    // const redisStore = await redis;
    // await redisStore.set(
    //   `refreshToken_${user.id}`,
    //   JSON.stringify({
    //     email,
    //     refreshToken,
    //   }),
    // );
    delete user.password;
    return { accessToken, refreshToken, user };
  }

  async refreshToken(userId: number, email: string) {
    const accessToken = await this.createAccessToken(userId, email);
    return { accessToken };
  }

  async logout(accessToken: string) {
    const redisStore = await redis;
    await redisStore.set(`blacklist_${accessToken}`, 1);
  }

  findUserByField(field: string, value: string) {
    return this.prisma.user.findFirst({
      where: {
        [field]: value,
      },
    });
  }
}
