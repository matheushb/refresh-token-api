import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Tokens } from './types';
import { AuthDto } from './dtos';
import { JwtPayload, JwtRefreshPayload } from './strategies';
import { Public, UserFromRequest } from './decorators';
import { JwtAuthGuard, JwtRefreshAuthGuard } from './guards';

@UseGuards(JwtAuthGuard)
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(signupDto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signupDto: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(signupDto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@UserFromRequest() user: JwtPayload): Promise<void> {
    this.authService.logout(user.sub);
  }

  @Post('refresh')
  @Public()
  @UseGuards(JwtRefreshAuthGuard)
  @HttpCode(HttpStatus.OK)
  async refresh(@UserFromRequest() user: JwtRefreshPayload): Promise<Tokens> {
    return this.authService.refresh(user.sub, user.refresh_token);
  }
}
