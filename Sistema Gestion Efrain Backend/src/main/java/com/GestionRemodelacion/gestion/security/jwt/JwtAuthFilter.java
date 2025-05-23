package com.GestionRemodelacion.gestion.security.jwt;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.GestionRemodelacion.gestion.model.RefreshToken;
import com.GestionRemodelacion.gestion.security.exception.TokenRefreshException;
import com.GestionRemodelacion.gestion.service.auth.RefreshTokenService;
import com.GestionRemodelacion.gestion.service.auth.TokenBlacklistService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro JWT mejorado con: - Manejo de errores robusto - Validación de token
 * revocado - Logging detallado
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final RefreshTokenService refreshTokenService;

    public JwtAuthFilter(JwtUtils jwtUtils,
            UserDetailsService userDetailsService,
            TokenBlacklistService tokenBlacklistService,
            RefreshTokenService refreshTokenService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = parseJwt(request);
            // 1. Validar token de acceso
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // Verificar si el access token está en la blacklist
                if (tokenBlacklistService.isBlacklisted(jwt)) {
                    LOGGER.warn("Intento de acceso con token revocado: {}", jwt.substring(jwt.length() - 6));
                    throw new TokenRefreshException(jwt, "Token de acceso revocado");
                }

                // Nueva verificación: estado del refresh token asociado
                // 2. Validar usuario
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);


            Optional<RefreshToken> refreshToken = refreshTokenService.findByUser(username);
            if (refreshToken.isPresent() && 
                (refreshToken.get().getExpiryDate().isBefore(Instant.now()) || 
                 refreshToken.get().isUsed())) {
                throw new TokenRefreshException(jwt, "Refresh token inválido");
            }                


                // 3. Establecer autenticación
                UsernamePasswordAuthenticationToken authentication
                        = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

                LOGGER.info("Usuario autenticado: {}", username);
            }
        } catch (TokenRefreshException | UsernameNotFoundException e) {
            LOGGER.error("Error en autenticación JWT: {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);

    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        return (headerAuth != null && headerAuth.startsWith("Bearer "))
                ? headerAuth.substring(7) : null;
    }
}
