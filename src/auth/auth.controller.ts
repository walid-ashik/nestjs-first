import { Body, Controller, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto/auth.dto";

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {

    }

    @Post('signup')
    signup(@Body() dto: AuthDto) {
        return this.authService.signUp(dto);
    }

    @Post('login')
    login(@Body() dto: AuthDto) {
        return this.authService.login(dto);
    }
}