import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dtos';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async signupLocal(signupDto: AuthDto): Promise<Tokens> {
    signupDto.password = await this.hashData(signupDto.password);

    const user = await this.prismaService.user.create({
      data: {
        email: signupDto.email,
        password: signupDto.password,
      },
    });

    return await this.getTokens(signupDto.email, user.id);
  }

  async signinLocal(signupDto: AuthDto): Promise<Tokens> {
    const { email, password } = signupDto;

    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const passwordMatch = await this.compareData(password, user.password);
    if (!passwordMatch) throw new UnauthorizedException('Invalid credentials');

    return await this.getTokens(email, user.id);
  }

  async logout(id: string) {
    await this.prismaService.user.updateMany({
      where: {
        id,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }
  async refresh(id: string, rt: string): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: { id },
    });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const rtMatch = await this.compareData(rt, user.hashedRt);
    if (!rtMatch) throw new UnauthorizedException('Invalid credentials');

    return await this.getTokens(user.email, user.id);
  }

  private async getTokens(email: string, sub: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { email, sub },
        { secret: process.env.JWT_SECRET, expiresIn: 15 * 60 },
      ),
      this.jwtService.signAsync(
        { email, sub },
        { secret: process.env.JWT_REFRESH_SECRET, expiresIn: 7 * 24 * 60 * 60 },
      ),
    ]);

    await this.updateRtHash(sub, rt);
    return { access_token: at, refresh_token: rt };
  }

  private async updateRtHash(id: string, rt: string) {
    const hash = await this.hashData(rt);
    await this.prismaService.user.update({
      where: { id },
      data: { hashedRt: hash },
    });
  }

  private async compareData(data: string, hashedData: string) {
    return bcrypt.compare(data, hashedData);
  }

  private async hashData(data: string) {
    return await bcrypt.hash(data, 10);
  }
}
