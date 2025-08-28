// File: app/components/header/header.component.ts
import { Component, OnInit, EventEmitter, Output } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { User } from '../../models/user.model';
import { MatIcon, MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatMenuModule } from '@angular/material/menu';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  imports: [
    MatIconModule,
    MatListModule,
    MatIcon,
    MatToolbarModule,
    MatMenuModule,
    CommonModule,
  ],
})
export class HeaderComponent implements OnInit {
  @Output() toggleSidenav = new EventEmitter<void>();

  currentUser: User | null = null;

  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit(): void {
    // Subscribe to the current user
    this.authService.currentUser.subscribe((user: User | null): void => {
      this.currentUser = user;
    });
  }

  // ngOnInit(): void {
  //   // Subscribe to the current user
  //   this.authService.currentUser$.subscribe((user) => {
  //     this.currentUser = user;
  //   });
  // }
  onToggleSidenav(): void {
    this.toggleSidenav.emit();
  }

  // logout(): void {
  //   this.authService.logout().subscribe({
  //     next: () => {
  //       this.router.navigate(['/login']);
  //     },
  //     error: (err) => {
  //       console.error('Error during logout', err);
  //       // Still navigate to login on error
  //       this.router.navigate(['/login']);
  //     },
  //   });
  // }

  logout(): void {
    try {
      this.authService.logout();
    } catch (err) {
      console.error('Error during logout', err);
      // Fallback navigation
      this.router.navigate(['/login']);
    }
  }

  navigateToProfile(): void {
    this.router.navigate(['/profile']);
  }
}
// // // File: app/components/header/header.component.ts
// // import { Component, EventEmitter, Input, Output } from '@angular/core';
// // import { User } from '../../models/user.model';

// // @Component({
// //   selector: 'app-header',
// //   templateUrl: './header.component.html',
// //   styleUrls: ['./header.component.scss'],
// // })
// // export class HeaderComponent {
// //   @Input() user: User | null = null;
// //   @Output() logout = new EventEmitter<void>();

// //   onLogout(): void {
// //     this.logout.emit();
// //   }
// // }

// // header.component.ts
// import { Component } from '@angular/core';

// @Component({
//   selector: 'app-header',
//   template: `
//     <header class="header">
//       <div class="logo">
//         <h1>PDF Signature Tool</h1>
//       </div>
//       <nav class="navigation">
//         <ul>
//           <li><a href="#" routerLink="/dashboard">Dashboard</a></li>
//           <li><a href="#" routerLink="/documents">Documents</a></li>
//           <li><a href="#" routerLink="/signatures">Signatures</a></li>
//           <li><a href="#" routerLink="/settings">Settings</a></li>
//         </ul>
//       </nav>
//       <div class="user-menu">
//         <button class="user-btn">
//           <i class="fa fa-user"></i>
//           <span>User</span>
//         </button>
//       </div>
//     </header>
//   `,
//   styles: [
//     `
//       .header {
//         display: flex;
//         align-items: center;
//         justify-content: space-between;
//         padding: 0 20px;
//         height: 60px;
//         background-color: #333;
//         color: white;
//         box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
//       }
//       .logo h1 {
//         margin: 0;
//         font-size: 1.5rem;
//       }
//       .navigation ul {
//         display: flex;
//         list-style: none;
//         margin: 0;
//         padding: 0;
//       }
//       .navigation li {
//         margin: 0 15px;
//       }
//       .navigation a {
//         color: white;
//         text-decoration: none;
//         font-weight: 500;
//         transition: color 0.3s;
//       }
//       .navigation a:hover {
//         color: #4caf50;
//       }
//       .user-btn {
//         background: none;
//         border: none;
//         color: white;
//         display: flex;
//         align-items: center;
//         cursor: pointer;
//       }
//       .user-btn i {
//         margin-right: 8px;
//       }
//     `,
//   ],
// })
// export class HeaderComponent {}
