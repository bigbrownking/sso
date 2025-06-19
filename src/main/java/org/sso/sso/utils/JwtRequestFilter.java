package org.sso.sso.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtService;
    private final SessionService sessionService;

    // Define the same paths as in SecurityConfig
    private static final String[] PERMIT_ALL_ROUTES = {
            "/swagger-ui.html",
            "/swagger-ui/",
            "/v3/api-docs",
            "/v3/api-docs.yaml",
            "/v3/api-docs/swagger-config",
            "/swagger-resources",
            "/webjars",
            "/configuration",
            "/auth",
            "/params",
            "/ws"
    };

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String accessToken = getTokenFromCookie(request, "accessToken");
            if (accessToken != null) {
                Claims claims = jwtService.validateToken(accessToken);
                String username = claims.getSubject();
                String roles = claims.get("roles", String.class);
                String sessionId = claims.get("sessionId", String.class);

                if (!sessionService.isSessionActive(sessionId)) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session revoked");
                    return;
                }

                List<SimpleGrantedAuthority> authorities = Arrays.stream(roles.split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (JwtException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
            return;
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Add logging for debugging
        System.out.println("Checking path: " + path);

        // Check against all permitted routes
        for (String route : PERMIT_ALL_ROUTES) {
            if (path.startsWith(route)) {
                System.out.println("Path " + path + " matches route " + route + " - skipping filter");
                return true;
            }
        }

        // Additional specific checks for Swagger paths
        boolean shouldSkip = path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs") ||
                path.startsWith("/swagger-resources") ||
                path.startsWith("/webjars") ||
                path.startsWith("/configuration") ||
                path.equals("/swagger-ui.html") ||
                path.contains("swagger") ||
                path.contains("api-docs");

        if (shouldSkip) {
            System.out.println("Path " + path + " is Swagger-related - skipping filter");
        }

        return shouldSkip;
    }

    private String getTokenFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}