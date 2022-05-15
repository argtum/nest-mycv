import {BadRequestException, Injectable, NotFoundException} from "@nestjs/common";
import { UsersService }                                     from "./users.service";
import { randomBytes, scrypt as _script }  from "crypto";
import { promisify }                       from "util";
import { User }                            from "./user.entity";

const script = promisify(_script);

@Injectable()
export class AuthService {
  constructor(private userServices: UsersService) {}

  async singup(email: string, password: string) {
    const users: User[] = await this.userServices.find(email);

    if (users.length) {
      throw new BadRequestException('email in use');
    }

    const salt: string = randomBytes(8).toString('hex');
    const hash: Buffer = (await script(password, salt, 32)) as Buffer;
    const result: string = salt + '.' + hash.toString('hex');

    return await this.userServices.create(email, result);
  }

  async singIn(email: string, password: string) {
    const [user] = await this.userServices.find(email);

    if (!user) {
      throw new NotFoundException('user not found');
    }

    const [salt, storedHash] = user.password.split('.');
    const hash = (await script(password, salt, 32)) as Buffer;

    if (storedHash !== hash.toString('hex')) {
      throw new BadRequestException('bad password');
    }

    return user;
  }
}