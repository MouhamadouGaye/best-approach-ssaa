import { Injectable } from '@angular/core';
import {
  HttpClient,
  HttpErrorResponse,
  HttpHeaders,
} from '@angular/common/http';
import { BehaviorSubject, catchError, Observable, tap, throwError } from 'rxjs';
import { environment } from '../envirennements/environnement';
import {
  ApiResponse,
  AuthResponse,
  ResetPasswordRequest,
} from '../type/response';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private apiUrl = `${environment.apiUrl}/auth`;
  private tokenKey = 'auth_token';
  private userKey = 'user_data';
  private authSubject = new BehaviorSubject<boolean>(this.hasValidToken());

  constructor(private http: HttpClient, private router: Router) {}

  isLoggedIn(): boolean {
    const token = this.tokenKey;
    if (!token) {
      console.log('No token found');
      return false;
    }

    // Check if token is expired
    const expiration = localStorage.getItem('expires_at');
    if (!expiration) {
      console.log('No expiration found');
      return false;
    }

    const expiresAt = parseInt(expiration, 10);
    const now = new Date().getTime();

    const isExpired = now > expiresAt;

    console.log(
      'Token check - expiresAt:',
      expiresAt,
      'now:',
      now,
      'isExpired:',
      isExpired
    );

    return !isExpired;
  }
  // Changed to getter property
  get isAuthenticated(): boolean {
    return this.hasValidToken();
  }

  get authStatus(): Observable<boolean> {
    return this.authSubject.asObservable();
  }

  get token(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  get currentUser(): any {
    const userData = localStorage.getItem(this.userKey);
    return userData ? JSON.parse(userData) : null;
  }

  login(email: string, password: string): Observable<AuthResponse> {
    console.log('Attempting login with:', email);

    return this.http
      .post<AuthResponse>(`${this.apiUrl}/login`, { email, password })
      .pipe(
        tap((response) => {
          console.log('Login successful, response:', response);

          // Extract the token from response.data
          const token = response.data.accessToken;
          console.log('Extracted token:', token);

          this.setSession(response.data); // Pass the data object, not the whole response
          this.authSubject.next(true);

          // Navigate after successful login
          this.router.navigate(['/']);
        }),
        catchError((error: HttpErrorResponse) => {
          console.error('Login error:', error);
          console.error('Error details:', error.error);
          return throwError(
            () => new Error(error.error?.message || 'Login failed')
          );
        })
      );
  }

  private setSession(authData: any) {
    console.log('Setting session with authData:', authData);

    if (!authData?.accessToken) {
      console.error('No access token found in authData');
      return;
    }

    const token = authData.accessToken;
    const expiresIn = authData.expiresIn * 1000; // Convert to milliseconds
    const expiresAt = new Date().getTime() + expiresIn;

    // Store in localStorage
    localStorage.setItem('access_token', token);
    localStorage.setItem('expires_at', expiresAt.toString());
    localStorage.setItem('user', JSON.stringify(authData.user));

    console.log('Session set successfully');
  }

  register(payload: {
    username: string;
    email: string;
    password: string;
  }): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>(`${this.apiUrl}/register`, payload)
      .pipe(
        tap((response) => {
          this.setSession(response);
          this.authSubject.next(true);
        })
      );
  }

  // register(payload: {
  //   username: string;
  //   email: string;
  //   password: string;
  // }): Observable<ApiResponse> {
  //   return this.http.post<ApiResponse>(`${this.apiUrl}/register`, payload).pipe(
  //     tap((response) => {
  //       console.log('Registration successful:', response);
  //     }),
  //     catchError((error: HttpErrorResponse) => {
  //       console.error('Registration error:', error);
  //       return throwError(
  //         () => new Error(error.error?.message || 'Registration failed')
  //       );
  //     })
  //   );
  // }

  logout(): void {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.userKey);
    this.authSubject.next(false);
  }

  private hasValidToken(): boolean {
    const token = this.token;
    if (!token) return false;

    // Simple check if token is expired
    // In a real app, you'd probably decode the JWT and check the exp claim
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp > Date.now() / 1000;
    } catch (e) {
      return false;
    }
  }

  // Forgot password - request reset email
  forgotPassword(email: string): Observable<ApiResponse> {
    console.log('Requesting password reset for:', email);

    return this.http
      .post<ApiResponse>(`${this.apiUrl}/forgot-password`, null, {
        params: { email },
      })
      .pipe(
        tap((response) => {
          console.log('Password reset email sent:', response);
        }),
        catchError((error: HttpErrorResponse) => {
          console.error('Forgot password error:', error);
          return throwError(
            () =>
              new Error(error.error?.message || 'Failed to send reset email')
          );
        })
      );
  }

  // Reset password with token
  resetPassword(
    token: string,
    newPassword: string,
    confirmPassword: string
  ): Observable<ApiResponse> {
    console.log('Resetting password with token:', token);

    const request: ResetPasswordRequest = {
      newPassword,
      confirmPassword,
    };

    return this.http
      .post<ApiResponse>(
        `${this.apiUrl}/reset-password?token=${token}`,
        request
      )
      .pipe(
        tap((response) => {
          console.log('Password reset successful:', response);
        }),
        catchError((error: HttpErrorResponse) => {
          console.error('Reset password error:', error);
          return throwError(
            () => new Error(error.error?.message || 'Failed to reset password')
          );
        })
      );
  }
}
