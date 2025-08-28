// // File: app/components/sidenav/sidenav.component.ts
// import { Component, NgModule, OnInit } from '@angular/core';
// import { Router, NavigationEnd } from '@angular/router';
// import { filter } from 'rxjs/operators';
// import { AuthService } from '../../services/auth.service';
// import { User } from '../../models/user.model';
// import { MatIcon } from '@angular/material/icon';
// import { CommonModule } from '@angular/common';
// import { MatListModule } from '@angular/material/list';

// interface NavItem {
//   label: string;
//   icon: string;
//   route: string;
//   requiredRole?: string;
// }

// @Component({
//   selector: 'app-sidenav',
//   templateUrl: './sidenav.component.html',
//   styleUrls: ['./sidenav.component.scss'],
//   imports: [MatIcon, CommonModule, MatListModule, NgMole ],
// })
// export class SidenavComponent implements OnInit {
//   navItems: NavItem[] = [
//     { label: 'Dashboard', icon: 'dashboard', route: '/dashboard' },
//     { label: 'Documents', icon: 'description', route: '/documents' },
//     {
//       label: 'Upload Document',
//       icon: 'cloud_upload',
//       route: '/documents/upload',
//     },
//     { label: 'My Signatures', icon: 'gesture', route: '/signatures' },
//     { label: 'Settings', icon: 'settings', route: '/settings' },
//     { label: 'Users', icon: 'people', route: '/users', requiredRole: 'ADMIN' },
//   ];

//   currentUser: User | null = null;
//   activeRoute: string = '';

//   constructor(private router: Router, private authService: AuthService) {}

//   ngOnInit(): void {
//     // Track current route for active link styling
//     this.router.events
//       .pipe(filter((event) => event instanceof NavigationEnd))
//       .subscribe((event: any) => {
//         this.activeRoute = event.urlAfterRedirects;
//       });

//     // Get current user for role-based menu items
//     this.authService.currentUser.subscribe((user) => {
//       this.currentUser = user;
//     });
//   }

//   isLinkActive(route: string): boolean {
//     return this.activeRoute.startsWith(route);
//   }

//   hasRequiredRole(requiredRole?: string): boolean {
//     if (!requiredRole) return true;
//     return this.currentUser?.roles?.includes(requiredRole) || false;
//   }

//   navigateTo(route: string): void {
//     this.router.navigate([route]);
//   }
// }

// // File: app/components/sidenav/sidenav.component.ts
// import { Component } from '@angular/core';

// @Component({
//   selector: 'app-sidenav',
//   templateUrl: './sidenav.component.html',
//   styleUrls: ['./sidenav.component.scss'],
// })
// export class SidenavComponent {}

// sidenav.component.ts
import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-sidenav',
  template: `
    <div class="sidenav">
      <div class="sidenav-header">
        <h3>Tools</h3>
      </div>
      <ul class="sidenav-items">
        <li>
          <a href="#" routerLink="/upload" routerLinkActive="active"
            >Upload Document</a
          >
        </li>
        <li>
          <a href="#" routerLink="/sign" routerLinkActive="active"
            >Sign Document</a
          >
        </li>
        <li>
          <a href="#" routerLink="/manage" routerLinkActive="active"
            >Manage Documents</a
          >
        </li>
        <li>
          <a href="#" routerLink="/templates" routerLinkActive="active"
            >Templates</a
          >
        </li>
        <li>
          <a href="#" routerLink="/history" routerLinkActive="active"
            >History</a
          >
        </li>
      </ul>
      <div class="sidenav-footer">
        <button class="help-btn">
          <i class="fa fa-question-circle"></i>
          Help
        </button>

        <button class="logout-btn" (click)="logout()">
          <i class="fa fa-sign-out-alt"></i>
          Logout
        </button>
      </div>
    </div>
  `,
  styles: [
    `
      .sidenav {
        width: 250px;
        height: 100%;
        background-color: #f5f5f5;
        border-right: 1px solid #ddd;
        display: flex;
        flex-direction: column;
      }
      .sidenav-header {
        padding: 20px;
        border-bottom: 1px solid #ddd;
      }
      .sidenav-header h3 {
        margin: 0;
        color: #333;
      }
      .sidenav-items {
        list-style: none;
        padding: 0;
        margin: 0;
        flex-grow: 1;
      }
      .sidenav-items li {
        margin: 0;
      }
      .sidenav-items a {
        display: block;
        padding: 15px 20px;
        color: #333;
        text-decoration: none;
        transition: background-color 0.3s;
      }
      .sidenav-items a:hover {
        background-color: #e0e0e0;
      }
      .sidenav-items a.active {
        background-color: #007bff;
        color: white;
      }
      .sidenav-footer {
        padding: 20px;
        border-top: 1px solid #ddd;
      }
      .help-btn {
        width: 100%;
        padding: 10px;
        background-color: #4caf50;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .help-btn i {
        margin-right: 8px;
      }
    `,
  ],
})
export class SidenavComponent {
  constructor(private authService: AuthService, private router: Router) {}

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/login']);
  }
}
