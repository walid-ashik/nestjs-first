import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { AuthDto } from "./dto/auth.dto";
import * as argon from "argon2";

@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService) {

    }

    async signUp(dto: AuthDto) {

        const hash = await argon.hash(dto.password);

        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                }
            });

            delete user.hash;

            return user;
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                throw new ForbiddenException('Credentials taken');
            }
            throw error;
        }
    }

    async login(dto: AuthDto) {

        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        if (!user) throw new ForbiddenException('Credentials incorrect');


        const password = await argon.verify(user.hash, dto.password);

        if (!password) throw new ForbiddenException('Password incorrect');

        delete user.hash;

        return user;
    }

}