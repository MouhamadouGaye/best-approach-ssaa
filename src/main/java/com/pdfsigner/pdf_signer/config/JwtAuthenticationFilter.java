// package com.pdfsigner.pdf_signer.config;

// import java.io.IOException;

// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.pdfsigner.pdf_signer.util.JwtUtil;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// public class JwtAuthenticationFilter extends OncePerRequestFilter {

//     private final JwtUtil jwtUtil; // Your JWT utility class
//     private final UserDetailsService userDetailsService;

//     public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
//         this.jwtUtil = jwtUtil;
//         this.userDetailsService = userDetailsService;
//     }

//     @Override
//     protected void doFilterInternal(HttpServletRequest request,
//             HttpServletResponse response,
//             FilterChain filterChain) throws ServletException, IOException {

//         String authHeader = request.getHeader("Authorization");

//         if (authHeader != null && authHeader.startsWith("Bearer ")) {
//             String jwt = authHeader.substring(7);
//             String username = jwtUtil.extractUsername(jwt);

//             if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//                 UserDetails userDetails = userDetailsService.loadUserByUsername(username);

//                 if (jwtUtil.validateToken(jwt, userDetails)) {
//                     UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails,
//                             null, userDetails.getAuthorities());

//                     token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

//                     SecurityContextHolder.getContext().setAuthentication(token);
//                 }
//             }
//         }

//         filterChain.doFilter(request, response);
//     }
// }

// // package com.pdfsigner.pdf_signer.config;

// // import jakarta.servlet.FilterChain;
// // import jakarta.servlet.ServletException;
// // import jakarta.servlet.http.HttpServletRequest;
// // import jakarta.servlet.http.HttpServletResponse;

// // import org.springframework.beans.factory.annotation.Autowired;
// // import
// org.springframework.security.authentication.BadCredentialsException;
// // import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// // import org.springframework.security.core.context.SecurityContextHolder;
// // import org.springframework.security.core.userdetails.UserDetails;
// // import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// // import org.springframework.stereotype.Component;
// // import org.springframework.web.filter.OncePerRequestFilter;

// // import com.pdfsigner.pdf_signer.service.MyUserDetailsService;
// // import com.pdfsigner.pdf_signer.util.JwtUtil;

// // import java.io.IOException;

// // @Component
// // public class JwtAuthenticationFilter extends OncePerRequestFilter {

// // // Inject your UserDetailsService and JWT utils here
// // private final MyUserDetailsService userDetailsService;
// // private final JwtUtil jwtUtil;

// // public JwtAuthenticationFilter(MyUserDetailsService userDetailsService,
// JwtUtil jwtUtil) {
// // this.userDetailsService = userDetailsService;
// // this.jwtUtil = jwtUtil;
// // }

// // @Override
// // protected void doFilterInternal(HttpServletRequest request,
// // HttpServletResponse response,
// // FilterChain filterChain)
// // throws ServletException, IOException {

// // final String authHeader = request.getHeader("Authorization");
// // final String jwt;
// // final String username;

// // if (authHeader == null || !authHeader.startsWith("Bearer")) {
// // filterChain.doFilter(request, response);
// // return;
// // }

// // jwt = authHeader.substring(7);
// // username = jwtUtil.extractUsername(jwt);
// // System.out.println("|||||||||||||||| This is the user: " + username);

// // if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// // UserDetails userDetails = userDetailsService.loadUserByUsername(username);

// // if (jwtUtil.validateToken(jwt, userDetails)) {
// // UsernamePasswordAuthenticationToken authToken = new
// UsernamePasswordAuthenticationToken(userDetails,
// // null, userDetails.getAuthorities());

// // authToken.setDetails(new
// WebAuthenticationDetailsSource().buildDetails(request));
// // SecurityContextHolder.getContext().setAuthentication(authToken);
// // }
// // }

// // filterChain.doFilter(request, response);
// // }
// // }

package com.pdfsigner.pdf_signer.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pdfsigner.pdf_signer.service.MyUserDetailsService;
import com.pdfsigner.pdf_signer.util.JwtUtil;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

import java.io.IOException;

// @Component
// @RequiredArgsConstructor
// public class JwtAuthenticationFilter extends OncePerRequestFilter {

//     private final MyUserDetailsService userDetailsService;
//     private final JwtUtil jwtUtil;

//     @Override
//     protected void doFilterInternal(
//             HttpServletRequest request,
//             HttpServletResponse response,
//             FilterChain filterChain)
//             throws ServletException, IOException {

//         if (request.getServletPath().equals("/api/users/login")) {
//             filterChain.doFilter(request, response); // skip filter for login
//             return;
//         }

//         // // Skip filter for public endpoints
//         // String path = request.getRequestURI();
//         // logger.info("Processing request: " + request.getRequestURI());
//         // if (path.startsWith("/api/users/register") ||
//         // path.startsWith("/api/users/login") ||
//         // path.equals("/error")) {
//         // filterChain.doFilter(request, response);

//         // return;
//         // }

//         String authHeader = request.getHeader("Authorization");
//         if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//             filterChain.doFilter(request, response);
//             return;
//         }

//         String token = authHeader.substring(7);
//         String username = jwtUtil.extractUsername(token);
//         System.out.println("Username: " + username);

//         if (username != null &&
//                 SecurityContextHolder.getContext().getAuthentication() == null) {
//             UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//             if (jwtUtil.validateToken(token, userDetails)) {
//                 UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
//                         null, userDetails.getAuthorities());
//                 authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                 SecurityContextHolder.getContext().setAuthentication(authToken);
//             }
//         }

//         filterChain.doFilter(request, response);
//     }
// }

// @Slf4j
// @Component
// @RequiredArgsConstructor
// public class JwtAuthenticationFilter extends OncePerRequestFilter {

//     private final MyUserDetailsService userDetailsService;
//     private final JwtUtil jwtUtil;

//     @Override
//     protected void doFilterInternal(
//             HttpServletRequest request,
//             HttpServletResponse response,
//             FilterChain filterChain)
//             throws ServletException, IOException {

//         String authHeader = request.getHeader("Authorization");
//         if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//             filterChain.doFilter(request, response);
//             return;
//         }

//         String token = authHeader.substring(7);
//         log.info("Received JWT token: {}", token);

//         try {
//             String username = jwtUtil.extractUsername(token);
//             log.info("Extracted username from token: {}", username);

//             if (username != null &&
//                     SecurityContextHolder.getContext().getAuthentication() == null) {

//                 UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//                 log.info("Loaded user details: {}", userDetails.getUsername());

//                 if (jwtUtil.validateToken(token, userDetails)) {
//                     UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                             userDetails,
//                             null,
//                             userDetails.getAuthorities());

//                     authToken.setDetails(
//                             new WebAuthenticationDetailsSource().buildDetails(request));

//                     SecurityContextHolder.getContext().setAuthentication(authToken);
//                     log.info("Authentication set in security context");
//                 }
//             }
//         } catch (Exception e) {
//             log.error("JWT processing error: {}", e.getMessage());
//         }

//         filterChain.doFilter(request, response);
//     }
// }
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final MyUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    // @Override
    // protected void doFilterInternal(
    // HttpServletRequest request,
    // HttpServletResponse response,
    // FilterChain filterChain)
    // throws ServletException, IOException {

    // String authHeader = request.getHeader("Authorization");
    // if (authHeader == null || !authHeader.startsWith("Bearer ")) {
    // filterChain.doFilter(request, response);
    // return;
    // }

    // String token = authHeader.substring(7);

    // try {
    // String username = jwtUtil.extractUsername(token);

    // if (username != null &&
    // SecurityContextHolder.getContext().getAuthentication() == null) {

    // UserDetails userDetails = userDetailsService.loadUserByUsername(username);

    // if (jwtUtil.validateToken(token, userDetails)) {
    // UsernamePasswordAuthenticationToken authToken = new
    // UsernamePasswordAuthenticationToken(
    // userDetails,
    // null,
    // userDetails.getAuthorities());

    // authToken.setDetails(
    // new WebAuthenticationDetailsSource().buildDetails(request));

    // SecurityContextHolder.getContext().setAuthentication(authToken);
    // }
    // }
    // } catch (ExpiredJwtException e) {
    // log.warn("JWT token expired: {}", e.getMessage());
    // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
    // return;
    // } catch (JwtException | IllegalArgumentException e) {
    // log.error("Invalid JWT token: {}", e.getMessage());
    // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
    // return;
    // }

    // filterChain.doFilter(request, response);
    // }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String token = null;

        // Check header first
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        // Then check cookie
        if (token == null) {
            token = extractTokenFromCookie(request);
        }

        if (token != null) {
            try {
                String username = jwtUtil.extractUsername(token);

                if (username != null &&
                        SecurityContextHolder.getContext().getAuthentication() == null) {

                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    if (jwtUtil.validateToken(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                        authToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            } catch (ExpiredJwtException e) {
                log.warn("JWT token expired: {}", e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
                return;
            } catch (JwtException | IllegalArgumentException e) {
                log.error("Invalid JWT token: {}", e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("jwt".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

}