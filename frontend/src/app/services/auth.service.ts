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
  LoginResponse,
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
  // Add these ⬇️
  private accessToken: string | null = null;
  private expiresAt: number | null = null;

  constructor(private http: HttpClient, private router: Router) {}

  // Changed to getter property
  get isAuthenticated(): boolean {
    return this.hasValidToken();
  }

  get authStatus(): Observable<boolean> {
    return this.authSubject.asObservable();
  }

  // get token(): string | null {
  //   return localStorage.getItem(this.tokenKey);
  // }

  // Optionally expose them through getters
  get token(): string | null {
    return this.accessToken;
  }

  get isTokenExpired(): boolean {
    return !this.expiresAt || Date.now() > this.expiresAt;
  }

  get currentUser(): any {
    const userData = localStorage.getItem(this.userKey);
    return userData ? JSON.parse(userData) : null;
  }

  // login(email: string, password: string): Observable<AuthResponse> {
  //   console.log('Attempting login with:', email);

  //   return this.http
  //     .post<AuthResponse>(`${this.apiUrl}/login`, { email, password })
  //     .pipe(
  //       tap((response) => {
  //         console.log('Login successful, response:', response);

  //         // Extract the token from response.data
  //         const token = response.data.accessToken;
  //         console.log('Extracted token:', token);

  //         this.setSession(response.data); // Pass the data object, not the whole response
  //         this.authSubject.next(true);

  //         // Navigate after successful login
  //         this.router.navigate(['/']);
  //       }),
  //       catchError((error: HttpErrorResponse) => {
  //         console.error('Login error:', error);
  //         console.error('Error details:', error.error);
  //         return throwError(
  //           () => new Error(error.error?.message || 'Login failed')
  //         );
  //       })
  //     );
  // }

  // login(email: string, password: string): Observable<AuthResponse> {
  //   return this.http
  //     .post<AuthResponse>(
  //       `${this.apiUrl}/login`,
  //       { email, password },
  //       { withCredentials: true }
  //     )
  //     .pipe(
  //       tap((res) => {
  //         // this.accessToken = res.data.accessToken; // keep in memory
  //         // this.expiresAt = Date.now() + res.data.expiresIn * 1000;
  //         this.authSubject.next(true);

  //       }),
  //       catchError((error: HttpErrorResponse) => {
  //         return throwError(
  //           () => new Error(error.error?.message || 'Login failed')
  //         );
  //       })
  //     );
  // }

  // login(email: string, password: string): Observable<any> {
  //   return this.http
  //     .post(
  //       `${this.apiUrl}/login`,
  //       { email, password },
  //       { withCredentials: true }
  //     )
  //     .pipe(
  //       tap(() => {
  //         // No token in JS, but we can set logged-in state
  //         this.authSubject.next(true);
  //       })
  //     );
  // }

  login(email: string, password: string): Observable<any> {
    return this.http
      .post(
        `${this.apiUrl}/login`,
        { email, password },
        { withCredentials: true }
      )
      .pipe(
        tap(() => {
          this.authSubject.next(true); // logged-in state
        }),
        catchError((error: HttpErrorResponse) => {
          // Extract message from backend
          let message = 'Login failed';
          if (error.error?.message) {
            message = error.error.message;
          } else if (error.status === 0) {
            message = 'Cannot connect to server';
          }
          return throwError(() => new Error(message));
        })
      );
  }

  isLoggedIn(): boolean {
    // Only rely on BehaviorSubject or make backend call
    return this.authSubject.value;
  }

  // Called by an interceptor on 401 or when token is near expiry
  refresh(): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>(
        `${this.apiUrl}/refresh`,
        {},
        { withCredentials: true }
      )
      .pipe(
        tap((res) => {
          this.accessToken = res.data.accessToken;
          this.expiresAt = Date.now() + res.data.expiresIn * 1000;
        })
      );
  }
  // Optional: call backend to refresh state
  refreshAuthStatus(): Observable<any> {
    return this.http.get(`${this.apiUrl}/me`, { withCredentials: true }).pipe(
      tap(() => this.authSubject.next(true)),
      catchError(() => {
        this.authSubject.next(false);
        return throwError(() => new Error('Not authenticated'));
      })
    );
  }

  private setSession(authData: AuthResponse): void {
    console.log('Setting session with authData:', authData);

    const loginData = authData.data;
    if (!loginData?.accessToken) {
      console.error('No access token found in authData');
      return;
    }

    const token = loginData.accessToken;
    const expiresIn = loginData.expiresIn * 1000; // Convert to milliseconds
    const expiresAt = new Date().getTime() + expiresIn;

    // Store in localStorage
    localStorage.setItem('access_token', token);
    localStorage.setItem('expires_at', expiresAt.toString());
    localStorage.setItem('user', JSON.stringify(loginData.user));

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
        tap((response: AuthResponse) => {
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
