import { Model, Page, QueryContext } from 'objection';

declare module 'objection-password' {
  class PasswordQueryBuilder<M extends Model, R = M[]> {
    ArrayQueryBuilderType: PasswordQueryBuilder<M, M[]>;
    SingleQueryBuilderType: PasswordQueryBuilder<M, M>;
    NumberQueryBuilderType: PasswordQueryBuilder<M, number>;
    PageQueryBuilderType: PasswordQueryBuilder<M, Page<M>>;
  }

  interface PasswordInstance<T extends typeof Model> {
    QueryBuilderType: PasswordQueryBuilder<this & T['prototype']>;

    $beforeInsert(context: QueryContext): Promise<string | void>;
    $beforeUpdate(queryOptions: object, context: QueryContext): Promise<string | void | undefined>
    verifyPassword(password: string): Promise<boolean>;
    generateHash(): Promise<string | void>;
  }

  interface PasswordStatic<T extends typeof Model> {
    QueryBuilder: typeof PasswordQueryBuilder;

    isBcryptHash(str: string): boolean;

    new(): PasswordInstance<T> & T['prototype'];
  }

  export default function (options?: {
    allowEmptyPassword?: boolean;
    passwordField?: string;
    rounds?: number;
  }): <T extends typeof Model>(model: T) => PasswordStatic<T> & Omit<T, 'new'> & T['prototype'];
}
