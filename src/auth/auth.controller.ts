import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { z } from 'zod';
import { AuthService } from './auth.service';
import { LoginAuthDto } from './dto/login-auth.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  async register(@Body() body: RegisterAuthDto, @Res() res: Response) {
    const schema = z.object({
      name: z
        .string({
          required_error: 'Tên bắt buộc phải nhập',
        })
        .min(4, 'Tên phải chứa ít nhất 4 ký tự'),
      email: z
        .string({
          required_error: 'Email bắt buộc phải nhập',
        })
        .email('Email không đúng định dạng')
        .refine(async (email) => {
          const user = await this.authService.findUserByField('email', email);
          return !user;
        }, 'Email đã có người sử dụng'),
      password: z
        .string({
          required_error: 'Mật khẩu bắt buộc phải nhập',
        })
        .min(6, 'Mật khẩu phải chứa ít nhất 6 ký tự'),
    });
    // Xử lý validate body (nếu schema sử dụng async => schema.safeParseAsync(body))
    const validatedFields = await schema.safeParseAsync(body);
    if (!validatedFields.success) {
      const errors = validatedFields.error.flatten().fieldErrors;
      const errorMessage = errors[Object.keys(errors)[0]][0];
      return res.status(HttpStatus.BAD_REQUEST).json({
        success: false,
        message: errorMessage,
      });
    }
    const data = await this.authService.register(body);
    return res.status(HttpStatus.CREATED).json({
      success: true,
      message: 'Đăng ký tài khoản thành công',
      data: data,
    });
  }

  @Post('/login')
  async login(@Body() { email, password }: LoginAuthDto, @Res() res: Response) {
    if (!email || !password) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        success: false,
        message: 'Vui lòng nhập email và mật khẩu',
      });
    }
    const data = await this.authService.login({ email, password });
    if (!data) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        success: false,
        message: 'Email hoặc mật khẩu chưa chính xác',
      });
    }
    return res.status(HttpStatus.OK).json({
      success: true,
      message: 'Đăng nhập thành công',
      data: data,
    });
  }

  @UseGuards(AuthGuard('jwt-at'))
  @Post('/logout')
  async logout(@Req() req, @Res() res: Response) {
    const user = req.user;
    await this.authService.logout(user.accessToken);
    return res.status(HttpStatus.OK).json({
      success: true,
      message: 'Đăng xuất thành công',
    });
  }

  @UseGuards(AuthGuard('jwt-rt'))
  @Post('/refreshToken')
  async refreshToken(@Req() req, @Res() res: Response) {
    const user = req.user;
    const data = await this.authService.refreshToken(user.userId, user.email);
    return res.status(HttpStatus.OK).json({
      success: true,
      message: 'SUCCESS',
      data: { ...data, refreshToken: user.refreshToken },
    });
  }

  @UseGuards(AuthGuard('jwt-at'))
  @Get('/me')
  async me(@Req() req, @Res() res: Response) {
    const user = req.user;
    const data = await this.authService.findUserByField('id', user.userId);
    if (!data) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        success: false,
        message: 'FAILED',
      });
    }
    delete data.password;
    return res.status(HttpStatus.OK).json({
      success: true,
      message: 'SUCCESS',
      data: data,
    });
  }
}
