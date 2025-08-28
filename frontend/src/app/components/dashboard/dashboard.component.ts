// // File: app/components/dashboard/dashboard.component.ts
// import { Component } from '@angular/core';
// import { Router } from '@angular/router';
// import { AuthService } from '../../services/auth.service';
// import { User } from '../../models/user.model';

// @Component({
//   selector: 'app-dashboard',
//   templateUrl: './dashboard.component.html',
//   styleUrls: ['./dashboard.component.scss'],
// })
// export class DashboardComponent {
//   currentUser: User | null = null;

//   constructor(private authService: AuthService, private router: Router) {
//     this.authService.currentUser$.subscribe((user) => {
//       this.currentUser = user;
//     });
//   }

//   logout(): void {
//     this.authService.logout();
//     this.router.navigate(['/login']);
//   }
// }

// dashboard.component.ts
import { Component, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { HeaderComponent } from '../header/header.component';
import { SidenavComponent } from '../sidenav/sidenav.component';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  template: `
    <div class="dashboard-container">
      <app-header></app-header>
      <div class="content-wrapper">
        <app-sidenav></app-sidenav>
        <div class="main-content">
          <router-outlet></router-outlet>
        </div>
      </div>
    </div>
  `,
  styles: [
    `
      .dashboard-container {
        display: flex;
        flex-direction: column;
        height: 100vh;
      }
      .content-wrapper {
        display: flex;
        flex: 1;
        overflow: hidden;
      }
      .main-content {
        flex: 1;
        overflow-y: auto;
        background-color: #f9f9f9;
      }
    `,
  ],
  imports: [HeaderComponent, SidenavComponent, RouterOutlet],
})
export class DashboardComponent {}
