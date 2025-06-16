package org.sso.sso.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.sso.sso.service.IUserService;

import org.sso.sso.utils.JwtTokenUtil;
import org.sso.sso.utils.SessionService;

import java.util.HashMap;
import java.util.Map;

@RestController
@AllArgsConstructor
public class AuthController {
    private final JwtTokenUtil jwtTokenUtil;

    private final SessionService sessionService;
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/refresh-access-token")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = getTokenFromCookie(request, "refreshToken");

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Refresh token not found"));
            }

            Claims refreshClaims = jwtTokenUtil.validateToken(refreshToken);
            String sessionId = refreshClaims.get("sessionId", String.class);

            if (!sessionService.isSessionActive(sessionId)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Session expired or invalid"));
            }

            String subject = refreshClaims.getSubject();
            Long userId = jwtTokenUtil.getUserIdFromToken(refreshToken);

            String roles = "ANALYST";
            String status = "ACTIVE";

            String newAccessToken = jwtTokenUtil.generateAccessToken(subject, userId, roles, status, sessionId);

            Cookie accessCookie = new Cookie("accessToken", newAccessToken);
            accessCookie.setHttpOnly(true);
            accessCookie.setSecure(true);
            accessCookie.setPath("/");
            accessCookie.setMaxAge((int) jwtTokenUtil.getAccessTokenExpiration() / 1000);
            accessCookie.setAttribute("SameSite", "Strict");
            response.addCookie(accessCookie);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("message", "Access token refreshed successfully");
            responseBody.put("tokenType", "Bearer");

            return ResponseEntity.ok(responseBody);

        } catch (ExpiredJwtException e) {
            String sessionId = e.getClaims().get("sessionId", String.class);
            if (sessionId != null) {
                sessionService.invalidateSession(sessionId);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Refresh token expired"));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid refresh token"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = getTokenFromCookie(request, "refreshToken");
            if (refreshToken != null) {
                try {
                    Claims claims = jwtTokenUtil.validateToken(refreshToken);
                    String sessionId = claims.get("sessionId", String.class);
                    sessionService.invalidateSession(sessionId);
                } catch (JwtException ignored) {
                }
            }
            clearCookie(response, "accessToken");
            clearCookie(response, "refreshToken");
            return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
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

    private void clearCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
