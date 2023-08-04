package com.micael.security.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
/**
 * This method is responsible for processing incoming HTTP requests and handling authentication with JSON Web Tokens (JWT).
 * It checks for the presence of a JWT in the Authorization header of the request, extracts the user's email from the token,
 * and validates the token's authenticity against the user details stored in the database.
 * If the JWT is valid and the user is not already authenticated, it creates an authenticated token using the user details,
 * sets it in the SecurityContextHolder, and proceeds with the request.
 * If the JWT is missing or not properly formatted, the request is allowed to continue without authentication.
 *
 * @param request     The incoming HttpServletRequest object.
 * @param response    The outgoing HttpServletResponse object.
 * @param filterChain The chain of filters to be applied to the request and response.
 * @throws ServletException If there is an issue while processing the request.
 * @throws IOException      If there is an I/O error during the request handling.
 */
protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain) throws ServletException, IOException {
    final String authHeader = request.getHeader("Authorization");
    final String jwt;
    final String userEmail;

    // Check if Authorization header exists and starts with "Bearer ".
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        // If not, proceed with the request without authentication.
        filterChain.doFilter(request, response);
        return;
    }

    // Extract the JWT from the Authorization header.
    jwt = authHeader.substring(7);
    // Extract the user's email from the JWT.
    userEmail = jwtService.extractUsername(jwt);

    // Check if the user's email is extracted and the user is not already authenticated.
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        // Load user details from the database using the email.
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

        // Check if the JWT is valid for the user.
        if (jwtService.isTokenValid(jwt, userDetails)) {
            // Create an authenticated token using the user details and set it in the SecurityContextHolder.
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
    }

    // Continue with the request processing.
    filterChain.doFilter(request, response);
}

}
