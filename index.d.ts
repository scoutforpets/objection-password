declare module 'objection-password' {
  import { Model } from 'objection';

  interface PasswordInstance extends Model {

    verifyPassword(password: string): Promise<boolean>;
    generateHash(): Promise<string | void>;

  }

  type Constructor<T = {}> = new (...args: any[]) => T;

  export default function (options?: {
    allowEmptyPassword?: boolean;
    passwordField?: string;
    rounds?: number;
  }): <T extends typeof Model>(model: T) => T & Constructor<PasswordInstance>
}
