// // main.ts
// import { bootstrapApplication } from '@angular/platform-browser';
// import { AppComponent } from './app/app.component';
// import { provideRouter } from '@angular/router';
// import { routes } from './app/app.routes';
// import { provideHttpClient, withInterceptors } from '@angular/common/http';
// import { provideAnimations } from '@angular/platform-browser/animations';
// import { AuthInterceptor } from './app/services/auth.interceptor';

// bootstrapApplication(AppComponent, {
//   providers: [
//     provideRouter(routes),
//     provideAnimations(),
//     provideHttpClient(withInterceptors([AuthInterceptor])),
//   ],
// });

// // import { bootstrapApplication } from '@angular/platform-browser';
// // import { provideRouter } from '@angular/router';
// // import { provideHttpClient, withInterceptors } from '@angular/common/http';
// // import { provideAnimations } from '@angular/platform-browser/animations';

// // import { AppComponent } from './app/app.component';
// // import { routes } from './app/app.routes';
// // import { authInterceptor } from './app/services/auth.interceptor';

// // bootstrapApplication(AppComponent, {
// //   providers: [
// //     provideRouter(routes),
// //     provideHttpClient(withInterceptors([authInterceptor])),
// //     provideAnimations(),
// //   ],
// // }).catch((err) => console.error(err));

// import { bootstrapApplication } from '@angular/platform-browser';
// import { provideRouter } from '@angular/router';
// import { provideHttpClient, withInterceptors } from '@angular/common/http';
// import { provideAnimations } from '@angular/platform-browser/animations';
// import { inject } from '@angular/core';

// import { AppComponent } from './app/app.component';
// import { routes } from './app/app.routes';
// // Fixed import name to match the exported class
// import { AuthInterceptor } from './app/services/auth.interceptor';
// bootstrapApplication(AppComponent, {
//   providers: [
//     provideRouter(routes),
//     provideHttpClient(
//       withInterceptors([
//         (req, next) => {
//           const authInterceptor = inject(AuthInterceptor);
//           return authInterceptor.intercept(req, { handle: next });
//         },
//       ])
//     ),
//     provideAnimations(),
//   ],
// }).catch((err) => console.error(err));

// import { bootstrapApplication } from '@angular/platform-browser';
// import { AppComponent } from './app/app.component';
// import { provideRouter } from '@angular/router';
// import { routes } from './app/app.routes';
// import {
//   HTTP_INTERCEPTORS,
//   provideHttpClient,
//   withInterceptorsFromDi,
// } from '@angular/common/http';
// import { AuthInterceptor } from './app/services/auth.interceptor';

// bootstrapApplication(AppComponent, {
//   providers: [
//     provideRouter(routes),
//     provideHttpClient(withInterceptorsFromDi()),
//     {
//       provide: HTTP_INTERCEPTORS,
//       useClass: AuthInterceptor,
//       multi: true,
//     },
//   ],
// });

// // main.ts
// import { bootstrapApplication } from '@angular/platform-browser';
// import { AppComponent } from './app/app.component';
// import { provideRouter } from '@angular/router';
// import { routes } from './app/app.routes';
// import { provideHttpClient, withInterceptors } from '@angular/common/http';
// import { provideAnimations } from '@angular/platform-browser/animations';
// import { AuthInterceptor } from './app/services/auth.interceptor';
// import { inject } from '@angular/core';

// bootstrapApplication(AppComponent, {
//   providers: [
//     provideRouter(routes),
//     provideAnimations(),
//     provideHttpClient(
//       withInterceptors([
//         (req, next) => {
//           const authInterceptor = inject(AuthInterceptor);
//           return authInterceptor.intercept(req, { handle: next });
//         },
//       ])
//     ),
//   ],
// });

import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { provideRouter } from '@angular/router';
import { routes } from './app/app.routes';
import {
  provideHttpClient,
  withInterceptorsFromDi,
} from '@angular/common/http';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes),
    provideHttpClient(withInterceptorsFromDi()), // ✅ this will discover interceptors with `providedIn: 'root'`
  ],
});
