import * as bcrypt from 'bcrypt';
const saltOrRounds = 10;

export default class Hash {
  static make(password: string) {
    return bcrypt.hashSync(password, saltOrRounds);
  }
  static verify(password: string, hash: string) {
    return bcrypt.compareSync(password, hash);
  }
}
