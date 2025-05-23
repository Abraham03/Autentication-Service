package com.GestionRemodelacion.gestion.service.auth;

import java.util.Date;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.GestionRemodelacion.gestion.dto.request.LoginRequest;
import com.GestionRemodelacion.gestion.dto.request.RefreshTokenRequest;
import com.GestionRemodelacion.gestion.dto.response.AuthResponse;
import com.GestionRemodelacion.gestion.model.RefreshToken;
import com.GestionRemodelacion.gestion.model.Role;
import com.GestionRemodelacion.gestion.model.User;
import com.GestionRemodelacion.gestion.security.jwt.JwtUtils;
import com.GestionRemodelacion.gestion.service.impl.UserDetailsImpl;

/**
 * Servicio de autenticación con: - Manejo de transacciones - Rotación de tokens
 * - Validación de credenciales - Inyección de dependencias
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthService(AuthenticationManager authenticationManager,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService,
            TokenBlacklistService tokenBlacklistService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Transactional
    public AuthResponse authenticate(LoginRequest request) {
    try {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()));
        
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        // Generar tokens
        String jwtToken = jwtUtils.generateJwtToken(authentication);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        
        logger.info("Autenticación exitosa para: {}", request.getUsername());
        
        return new AuthResponse(
            jwtToken,
            userDetails.getId(),
            userDetails.getUsername(),
            userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()),
            jwtUtils.getExpirationDateFromToken(jwtToken),
            refreshToken.getToken()
        );
    } catch (BadCredentialsException e) {
        logger.warn("Intento fallido de login para: {}", request.getUsername());
        throw new BadCredentialsException("Credenciales inválidas");
    }
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {

        // 1. Validar refresh token
        RefreshToken refreshToken = refreshTokenService.rotateRefreshToken(request.getRefreshToken());

        // 2. Generar nuevo access token
        User user = refreshToken.getUser();
        String newJwtToken = jwtUtils.generateTokenFromUsername(
            user.getUsername(),
            user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList())
        );

        // 3. Registrar en logs
        logger.info("Tokens rotados para usuario: {}", user.getUsername());

        return new AuthResponse(
            newJwtToken,
            user.getId(),
            user.getUsername(),
            user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList()),
            jwtUtils.getExpirationDateFromToken(newJwtToken),
            refreshToken.getToken()
        );
    }

    

    @Transactional
    public void logout(String token) {
        try {
            Date expirationDate = jwtUtils.getExpirationDateFromToken(token);
            tokenBlacklistService.blacklistToken(token, expirationDate.toInstant());
            refreshTokenService.revokeByToken(token);
        } catch (Exception e) {
            logger.error("Error durante logout: {}", e.getMessage());
            throw new RuntimeException("Error al cerrar sesión", e);
        }
    }

}
