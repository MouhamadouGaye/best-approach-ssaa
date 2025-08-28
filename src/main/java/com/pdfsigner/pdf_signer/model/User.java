// package com.pdfsigner.pdf_signer.model;

// import jakarta.persistence.*;
// import java.time.LocalDateTime;
// import java.util.Collection;
// import java.util.HashSet;
// import java.util.Set;
// import java.util.stream.Collectors;

// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;

// @Entity
// @Table(name = "users")
// public class User {

//     @Id
//     @GeneratedValue(strategy = GenerationType.IDENTITY)
//     private Long id;

//     @Column(nullable = false, unique = true)
//     private String username;

//     @Column(nullable = false)
//     private String password;

//     @Column(nullable = false, unique = true)
//     private String email;

//     // @ManyToMany(fetch = FetchType.EAGER) // Eager fetching ensures roles are
//     // always loaded
//     // @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"),
//     // inverseJoinColumns = @JoinColumn(name = "role_id"))
//     // private Set<Role> roles = new HashSet<>(); I replace this with the one below

//     // With this LAZY loading version:
//     @ManyToMany(fetch = FetchType.LAZY)
//     @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
//     private Set<Role> roles = new HashSet<>();

//     @Column(name = "created_at")
//     private LocalDateTime createdAt;

//     // sGetters and Setters
//     public Long getId() {
//         return id;
//     }

//     public void setId(Long id) {
//         this.id = id;
//     }

//     public String getUsername() {
//         return username;
//     }

//     public void setUsername(String username) {
//         this.username = username;
//     }

//     public String getPassword() {
//         return password;
//     }

//     public void setPassword(String password) {
//         this.password = password;
//     }

//     public String getEmail() {
//         return email;
//     }

//     public void setEmail(String email) {
//         this.email = email;
//     }

//     public LocalDateTime getCreatedAt() {
//         return createdAt;
//     }

//     public void setCreatedAt(LocalDateTime createdAt) {
//         this.createdAt = createdAt;
//     }

//     public Set<Role> getRoles() {
//         return roles;
//     }

//     public void setRoles(Set<Role> roles) {
//         this.roles = roles;
//     }

//     // Add this helper method for Spring Security:
//     public Collection<? extends GrantedAuthority> getAuthorities() {
//         return this.roles.stream()
//                 .map(role -> new SimpleGrantedAuthority(role.))
//                 .collect(Collectors.toList());
//     }

// }

package com.pdfsigner.pdf_signer.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor // 👈 Required by Hibernate
@AllArgsConstructor
@Builder // Still allows builder pattern
@ToString(exclude = "password") // Exclude password from toString
public class User implements Serializable { // Added Serializable for JWT compatibility

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    // Enum-based role implementation
    @ElementCollection(fetch = FetchType.EAGER) // Eager is okay for small collections
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>();

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private VerificationToken verificationToken;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "last_login_at", nullable = false)
    private LocalDateTime lastLoginAt;

    @Column(name = "enable", nullable = false)
    private boolean enabled = false;

    @Column(name = "account_non_expired", nullable = false)
    private boolean accountNonExpired = true;

    @Column(name = "account_non_locked", nullable = false)
    private boolean accountNonLocked = true;

    @Column(name = "credentials_non_expired", nullable = false)
    private boolean credentialsNonExpired = true;

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    // Updated authorities helper method
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toList());
    }
}