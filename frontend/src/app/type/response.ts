export interface LoginResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  user: UserDto;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  data: LoginResponse;
  timestamp: string | null;
}

export interface UserDto {
  id: number;
  email: string;
  username: string;
  roles: string[];
  createdAt: string;
  enabled: boolean;
  lastLoginAt: string | null;
}

// export interface ApiResponse {
//   success: boolean;
//   message: string;
//   data?: any;
//   timestamp?: string | null;
// }

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data: T; // generic type, since "Object" can be anything
  timestamp: string; // LocalDateTime is serialized to ISO string in JSON
}

export interface ResetPasswordRequest {
  newPassword: string;
  confirmPassword: string;
}
