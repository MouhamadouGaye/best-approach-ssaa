// File: app/services/auth.interceptor.ts
import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root', // 🔴 This is essential for `withInterceptorsFromDi()` to discover it!
})
export class AuthInterceptor implements HttpInterceptor {
  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const token = localStorage.getItem('token');

    if (token) {
      const authReq = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
      });
      return next.handle(authReq);
    }

    return next.handle(req);
  }
}

// // // auth.interceptor.ts
// // import { HttpInterceptorFn } from '@angular/common/http';
// // import { inject } from '@angular/core';
// // import { AuthService } from './auth.service';

// // export const authInterceptor: HttpInterceptorFn = (req, next) => {
// //   const authService = inject(AuthService);
// //   const token = authService.getToken(); // Assuming you have a method to get the token

// //   if (token) {
// //     const cloned = req.clone({
// //       setHeaders: {
// //         Authorization: `Bearer ${token}`,
// //       },
// //     });
// //     return next(cloned);
// //   }

// //   return next(req);
// // };

// import { Injectable } from '@angular/core';
// import {
//   HttpInterceptor,
//   HttpRequest,
//   HttpHandler,
//   HttpEvent,
// } from '@angular/common/http';
// import { Observable } from 'rxjs';

// @Injectable()
// export class AuthInterceptor implements HttpInterceptor {
//   intercept(
//     req: HttpRequest<any>,
//     next: HttpHandler
//   ): Observable<HttpEvent<any>> {
//     const authReq = req.clone({
//       setHeaders: {
//         Authorization: `Bearer your-token-here`,
//       },
//     });
//     return next.handle(authReq);
//   }
// }

// import { Injectable } from '@angular/core';
// import {
//   HttpRequest,
//   HttpHandler,
//   HttpEvent,
//   HttpInterceptor,
//   HttpErrorResponse,
// } from '@angular/common/http';
// import { Observable, throwError } from 'rxjs';
// import { catchError } from 'rxjs/operators';
// import { Router } from '@angular/router';
// import { AuthService } from './auth.service';

// @Injectable()
// export class AuthInterceptor implements HttpInterceptor {
//   constructor(private authService: AuthService, private router: Router) {}

//   intercept(
//     request: HttpRequest<unknown>,
//     next: HttpHandler
//   ): Observable<HttpEvent<unknown>> {
//     // Get the token from the auth service
//     const token = this.authService.token;

//     // If we have a token, add it to the request
//     if (token) {
//       request = request.clone({
//         setHeaders: {
//           Authorization: `Bearer ${token}`,
//         },
//       });
//     }

//     // Handle the request and catch any errors
//     return next.handle(request).pipe(
//       catchError((error: HttpErrorResponse) => {
//         // If we get a 401 Unauthorized response, the token is either invalid or expired
//         if (error.status === 401) {
//           this.authService.logout();
//           this.router.navigate(['/login']);
//         }
//         return throwError(() => error);
//       })
//     );
//   }
// }

// For use with provideHttpClient(withInterceptors([authInterceptorFn]))
// export function authInterceptorFn(
//   req: HttpRequest<unknown>,
//   next: HttpHandler
// ): Observable<HttpEvent<unknown>> {
//   const authService = new AuthService(null!); // Not ideal, but works for this example
//   const token = authService.token;

//   if (token) {
//     req = req.clone({
//       setHeaders: {
//         Authorization: `Bearer ${token}`,
//       },
//     });
//   }

//   return next.handle(req);
// }
