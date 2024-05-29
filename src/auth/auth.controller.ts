import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { authDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('signup')
    signup(@Body() dto: authDto){
       return this.authService.signup(dto)
    }

    @Post('signin')
    login(@Body() dto: authDto){
       return this.authService.login(dto)
    }
}
