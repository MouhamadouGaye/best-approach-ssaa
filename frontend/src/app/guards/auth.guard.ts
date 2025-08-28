// // File: app/services/auth.guard.ts
// import { Injectable } from '@angular/core';
// import { CanActivate, Router } from '@angular/router';
// import { AuthService } from './auth.service';

// @Injectable({
//   providedIn: 'root',
// })
// export class AuthGuard implements CanActivate {
//   constructor(private authService: AuthService, private router: Router) {}

//   canActivate(): boolean {
//     if (this.authService.isAuthenticated()) {
//       return true;
//     }

//     this.router.navigate(['/login']);
//     return false;
//   }
// }

import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import {
  CanActivate,
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
} from '@angular/router';
import { AuthService } from '../services/auth.service';
// import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root',
})
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  //   canActivate(
  //     route: ActivatedRouteSnapshot,
  //     state: RouterStateSnapshot
  //   ): boolean {
  //     // Fixed: Use isAuthenticated as a property, not as a method
  //     if (this.authService.isAuthenticated) {
  //       return true;
  //     }

  //     this.router.navigate(['/login'], {
  //       queryParams: { returnUrl: state.url },
  //     });
  //     return false;
  //   }
  // }

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    const isLoggedIn = this.authService.isLoggedIn();
    console.log(
      'AuthGuard checking - isLoggedIn:',
      isLoggedIn,
      'requested URL:',
      state.url
    );

    if (isLoggedIn) {
      return true;
    } else {
      console.log('Redirecting to login with returnUrl:', state.url);
      this.router.navigate(['/login'], {
        queryParams: { returnUrl: state.url },
      });
      return false;
    }
  }
}
