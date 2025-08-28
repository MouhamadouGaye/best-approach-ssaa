
// package com.pdfsigner.pdf_signer.util;

// import io.jsonwebtoken.*;
// import io.jsonwebtoken.security.Keys;
// import io.jsonwebtoken.security.SignatureException;

// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.security.Key;
// import java.util.Date;
// import java.util.List;
// import java.util.*;
// import java.util.stream.Collectors;

// @Component
// public class JwtUtil {

//     private final String SECRET_KEY;
//     private final long EXPIRATION_TIME;
//     private final Key SIGNING_KEY;

//     public JwtUtil(
//             @Value("${jwt.secret}") String secretKey,
//             @Value("${jwt.expiration}") long expirationTime) {
//         this.EXPIRATION_TIME = expirationTime;
//         this.SECRET_KEY = secretKey;

//         if (SECRET_KEY == null || SECRET_KEY.length() < 32) {
//             throw new IllegalArgumentException("JWT secret key must be at least 32 characters long.");
//         }

//         // Pre-calculate the signing key
//         this.SIGNING_KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
//     }

//     private Key getSigningKey() {
//         return SIGNING_KEY;
//     }

//     public String generateToken(UserDetails userDetails) {
//         Map<String, Object> claims = new HashMap<>();
//         claims.put("roles", userDetails.getAuthorities().stream()
//                 .map(GrantedAuthority::getAuthority)
//                 .collect(Collectors.toList()));

//         return Jwts.builder()
//                 .setClaims(claims)
//                 .setSubject(userDetails.getUsername())
//                 .setIssuedAt(new Date())
//                 .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
//                 .signWith(getSigningKey(), SignatureAlgorithm.HS256)
//                 .compact();
//     }

//     public String extractUsername(String token) {
//         return getClaimsFromToken(token).getSubject();
//     }

//     public boolean validateToken(String token, UserDetails userDetails) {
//         final String username = extractUsername(token);
//         return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
//     }

//     private boolean isTokenExpired(String token) {
//         Date expiration = getClaimsFromToken(token).getExpiration();
//         return expiration.before(new Date());
//     }

//     public List<String> extractRoles(String token) {
//         Claims claims = getClaimsFromToken(token);
//         List<?> roles = claims.get("roles", List.class);
//         return roles.stream()
//                 .map(Object::toString)
//                 .collect(Collectors.toList());
//     }

//     private Claims getClaimsFromToken(String token) {
//         try {
//             return Jwts.parserBuilder()
//                     .setSigningKey(getSigningKey())
//                     .build()
//                     .parseClaimsJws(token)
//                     .getBody();
//         } catch (ExpiredJwtException e) {
//             // Log expiration separately if needed
//             throw e;
//         } catch (UnsupportedJwtException | MalformedJwtException | SignatureException e) {
//             throw new JwtException("Invalid JWT token", e);
//         } catch (IllegalArgumentException e) {
//             throw new JwtException("JWT token compact of handler are invalid", e);
//         }
//     }
// }

package com.pdfsigner.pdf_signer.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.pdfsigner.pdf_signer.model.Role;
import com.pdfsigner.pdf_signer.model.User;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtUtil {

    private final String SECRET_KEY;
    private final long EXPIRATION_TIME;
    private final Key SIGNING_KEY;

    public JwtUtil(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.expiration}") long expirationTime) {
        this.EXPIRATION_TIME = expirationTime;
        this.SECRET_KEY = secretKey;

        if (SECRET_KEY == null || SECRET_KEY.length() < 32) {
            throw new IllegalArgumentException("JWT secret key must be at least 32 characters long.");
        }

        // Pre-calculate the signing key
        this.SIGNING_KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private Key getSigningKey() {
        return SIGNING_KEY;
    }

    // Method for UserDetails (existing)
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return buildToken(claims, userDetails.getUsername());
    }

    // NEW: Method for User entity
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("roles", user.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toList()));
        claims.put("enabled", user.isEnabled());

        return buildToken(claims, user.getEmail());
    }

    // NEW: Method with custom claims
    public String generateToken(User user, Map<String, Object> additionalClaims) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("roles", user.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toList()));
        claims.put("enabled", user.isEnabled());

        // Add any additional claims
        if (additionalClaims != null) {
            claims.putAll(additionalClaims);
        }

        return buildToken(claims, user.getEmail());
    }

    private String buildToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // NEW: Get expiration time in milliseconds
    public long getExpirationTimeMillis() {
        return EXPIRATION_TIME;
    }

    // NEW: Get expiration time in seconds
    public long getExpirationTimeSeconds() {
        return EXPIRATION_TIME / 1000;
    }

    // NEW: Get expiration date from token
    public Date getExpirationDateFromToken(String token) {
        return getClaimsFromToken(token).getExpiration();
    }

    // NEW: Get time until expiration in seconds
    public long getTimeUntilExpirationSeconds(String token) {
        Date expiration = getExpirationDateFromToken(token);
        long currentTime = System.currentTimeMillis();
        long expirationTime = expiration.getTime();
        return (expirationTime - currentTime) / 1000;
    }

    // NEW: Check if token will expire soon (within given seconds)
    public boolean willExpireSoon(String token, long secondsThreshold) {
        long timeUntilExpiration = getTimeUntilExpirationSeconds(token);
        return timeUntilExpiration <= secondsThreshold;
    }

    // NEW: Refresh token (extend expiration)
    public String refreshToken(String token) {
        Claims claims = getClaimsFromToken(token);
        claims.setIssuedAt(new Date());
        claims.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME));

        return Jwts.builder()
                .setClaims(claims)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // NEW: Extract user ID from token
    public Long extractUserId(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("userId", Long.class);
    }

    // NEW: Extract username from token (different from email/subject)
    public String extractUsernameFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("username", String.class);
    }

    // NEW: Check if user is enabled from token claims
    public boolean isUserEnabled(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("enabled", Boolean.class);
    }

    public String extractUsername(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    // NEW: Validate token for User entity
    public boolean validateToken(String token, User user) {
        final String username = extractUsername(token);
        final Long userId = extractUserId(token);

        return username.equals(user.getEmail()) &&
                userId.equals(user.getId()) &&
                !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public List<String> extractRoles(String token) {
        Claims claims = getClaimsFromToken(token);
        List<?> roles = claims.get("roles", List.class);
        return roles.stream()
                .map(Object::toString)
                .collect(Collectors.toList());
    }

    // NEW: Extract specific claim
    public <T> T extractClaim(String token, String claimName, Class<T> clazz) {
        Claims claims = getClaimsFromToken(token);
        return claims.get(claimName, clazz);
    }

    // NEW: Get all claims
    public Map<String, Object> extractAllClaims(String token) {
        Claims claims = getClaimsFromToken(token);
        return new HashMap<>(claims);
    }

    private Claims getClaimsFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
            throw new JwtException("Unsupported JWT token", e);
        } catch (MalformedJwtException e) {
            log.error("JWT token is malformed: {}", e.getMessage());
            throw new JwtException("Malformed JWT token", e);
        } catch (SignatureException e) {
            log.error("JWT signature validation failed: {}", e.getMessage());
            throw new JwtException("Invalid JWT signature", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT token compact of handler are invalid: {}", e.getMessage());
            throw new JwtException("JWT token compact of handler are invalid", e);
        }
    }
}