import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request, Response } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { redis } from 'src/utils/redis';

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt-at') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_AT_SECRET,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, res: Response, payload: any) {
    const accessToken = req.get('authorization')?.split(' ')[1];
    const redisStore = await redis;
    const blacklist = await redisStore.get(`blacklist_${accessToken}`);
    if (blacklist) {
      return false;
    }
    return {
      ...payload,
      accessToken,
    };
  }
}
