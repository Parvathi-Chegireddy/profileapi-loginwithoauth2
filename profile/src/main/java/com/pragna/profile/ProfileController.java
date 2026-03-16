package com.pragna.profile;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final JwtService jwtService;

    public ProfileController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * POST /api/profile/token
     *
     * Called internally by auth-service (9090) and oauth2-service (9092).
     * Returns:
     *   - accessToken in JSON body  (15 min, stored in React memory)
     *   - refreshToken as HttpOnly cookie (7 days, JS cannot read it)
     *   - profile fields in JSON body
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> issueToken(
            @RequestBody ProfileRequest req,
            HttpServletResponse response) {

        System.out.printf("[PROFILE] Issuing tokens → username=%s provider=%s method=%s%n",
                req.getUsername(), req.getProvider(), req.getLoginMethod());

        String username    = nvl(req.getUsername(),    "unknown");
        String role        = nvl(req.getRole(),        "ROLE_USER");
        String provider    = nvl(req.getProvider(),    "local");
        String loginMethod = nvl(req.getLoginMethod(), "regular");
        String email       = nvl(req.getEmail(),       "");
        String displayName = nvl(req.getDisplayName(), req.getUsername());
        String avatar      = nvl(req.getAvatar(),      "");

        // Issue access token — goes in response body
        String accessToken = jwtService.issueAccessToken(
                username, role, provider, loginMethod, email, displayName, avatar);

        // Issue refresh token — set as HttpOnly cookie
        String refreshToken = jwtService.issueRefreshToken(username);
        setRefreshTokenCookie(response, refreshToken);

        // Build response body — access token + profile info, NO refresh token
        Map<String, Object> body = new HashMap<>();
        body.put("accessToken",  accessToken);
        body.put("username",     username);
        body.put("displayName",  displayName);
        body.put("email",        email);
        body.put("avatar",       avatar);
        body.put("role",         role);
        body.put("provider",     provider);
        body.put("loginMethod",  loginMethod);
        body.put("roleLabel",    buildRoleLabel(req));
        body.put("methodLabel",  buildMethodLabel(req));
        body.put("expiresIn",    900); // 15 minutes in seconds

        return ResponseEntity.ok(body);
    }

    /**
     * POST /api/profile/refresh
     *
     * Called by React when access token expires (or on page load to restore session).
     * Reads refresh token from HttpOnly cookie — JS never touches it.
     * Returns a new access token if refresh token is valid.
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(
            HttpServletRequest request,
            HttpServletResponse response) {

        // Extract refresh token from HttpOnly cookie
        String refreshToken = extractRefreshCookie(request);

        if (refreshToken == null) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "No refresh token"));
        }

        if (!jwtService.isValid(refreshToken) || !jwtService.isRefreshToken(refreshToken)) {
            // Clear the invalid cookie
            clearRefreshTokenCookie(response);
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Refresh token invalid or expired"));
        }

        var claims = jwtService.validateAndGetClaims(refreshToken);
        String username = claims.getSubject();

        // Re-issue a fresh access token with same claims
        // In a real app you'd reload user from DB here to get latest role/email
        String newAccessToken = jwtService.issueAccessToken(
                username,
                "", // will be re-fetched — for demo we pass empty
                "local", "regular", "", username, ""
        );

        // Also rotate the refresh token — new cookie, old one invalidated
        String newRefreshToken = jwtService.issueRefreshToken(username);
        setRefreshTokenCookie(response, newRefreshToken);

        Map<String, Object> body = new HashMap<>();
        body.put("accessToken", newAccessToken);
        body.put("username",    username);
        body.put("expiresIn",   900);

        return ResponseEntity.ok(body);
    }

    /**
     * POST /api/profile/logout
     *
     * Clears the refresh token cookie.
     * Access token expires naturally (15 min max).
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response) {
        clearRefreshTokenCookie(response);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    /**
     * GET /api/profile/validate
     *
     * Validates an access token.
     * Called by gateway JwtAuthFilter on protected routes.
     */
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Missing Authorization header"));
        }

        String token = authHeader.substring(7);

        if (!jwtService.isValid(token) || !jwtService.isAccessToken(token)) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Token invalid or expired"));
        }

        var claims = jwtService.validateAndGetClaims(token);
        Map<String, Object> body = new HashMap<>();
        body.put("valid",       true);
        body.put("username",    claims.getSubject());
        body.put("role",        claims.get("role"));
        body.put("provider",    claims.get("provider"));
        body.put("loginMethod", claims.get("loginMethod"));
        body.put("email",       claims.get("email"));
        body.put("displayName", claims.get("displayName"));
        body.put("avatar",      claims.get("avatar"));
        return ResponseEntity.ok(body);
    }

    /* ── Cookie helpers ─────────────────────────────────── */

    private void setRefreshTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("refreshToken", token);
        cookie.setHttpOnly(true);   // JS cannot read this
        cookie.setSecure(false);    // Set true in production (HTTPS only)
        cookie.setPath("/api/profile/refresh"); // Only sent to refresh endpoint
        cookie.setMaxAge((int)(jwtService.getRefreshTokenExpiryMs() / 1000));
        // SameSite=Strict via header — Cookie API doesn't support it directly
        response.addCookie(cookie);
        response.addHeader("Set-Cookie",
                "refreshToken=" + token
                + "; Path=/api/profile/refresh"
                + "; HttpOnly"
                + "; Max-Age=" + (jwtService.getRefreshTokenExpiryMs() / 1000)
                + "; SameSite=Strict");
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie",
                "refreshToken=; Path=/api/profile/refresh"
                + "; HttpOnly; Max-Age=0; SameSite=Strict");
    }

    private String extractRefreshCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> "refreshToken".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    /* ── Label helpers ──────────────────────────────────── */

    private String buildRoleLabel(ProfileRequest req) {
        if ("ROLE_ADMIN".equals(req.getRole())) return "ADMIN";
        if ("oauth2".equals(req.getLoginMethod()) && req.getProvider() != null)
            return req.getProvider().toUpperCase() + " USER";
        return "USER";
    }

    private String buildMethodLabel(ProfileRequest req) {
        if ("oauth2".equals(req.getLoginMethod()) && req.getProvider() != null) {
            String p = req.getProvider();
            return Character.toUpperCase(p.charAt(0)) + p.substring(1) + " OAuth2";
        }
        return "Password Login";
    }

    private String nvl(String v, String fallback) {
        return (v != null && !v.isBlank()) ? v : fallback;
    }
}
