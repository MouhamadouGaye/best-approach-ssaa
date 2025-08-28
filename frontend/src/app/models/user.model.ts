// File: app/models/user.model.ts
export interface User {
  id?: number;
  username: string;
  email: string;
  password?: string;
  createdAt?: Date;
  roles?: string[];
}
