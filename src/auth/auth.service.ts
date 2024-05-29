import { ForbiddenException, HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { authDto } from './dto/auth.dto';
import * as  argon from 'argon2'
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(
        private Prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) { }

    async signup(dto: authDto) {
        try {
            const hash = await argon.hash(dto.password)
            const data = {
                email: dto.email,
                hash,
            }

            const user = await this.Prisma.user.create({ data })
            return this.signToken(user.id, user.email)

        } catch (error) {
            if(error instanceof PrismaClientKnownRequestError){
               if(error.code ==='P2002'){
                throw new ForbiddenException("Email is already taken")
               }
            }
            throw error
        }
    }

    async login(dto: authDto) {
       const user = await this.Prisma.user.findUnique({where: {email: dto.email}});
       if(!user){
        throw new ForbiddenException("Incorrent credentials");
       }
       const pverify = await argon.verify(user.hash, dto.password)
       if(!pverify ){
        throw new ForbiddenException("Incorrect credentials");
       }

      return this.signToken(user.id, user.email)
    }

   async signToken (userId: number, email: string): Promise<{access_token: string}>{
        const payload = {
            sub: userId,
            email
        }
        
        const SECRET = this.config.get("JWT_SECRET");
        
        const token = await this.jwt.signAsync(payload, {
            expiresIn:'60m', 
            secret: SECRET
        })

        return {
            access_token: token
        }
    }

}
