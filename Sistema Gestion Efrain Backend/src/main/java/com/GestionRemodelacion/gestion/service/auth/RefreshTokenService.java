package com.GestionRemodelacion.gestion.service.auth;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.GestionRemodelacion.gestion.model.RefreshToken;
import com.GestionRemodelacion.gestion.model.User;
import com.GestionRemodelacion.gestion.repository.RefreshTokenRepository;
import com.GestionRemodelacion.gestion.repository.UserRepository;
import com.GestionRemodelacion.gestion.security.exception.TokenRefreshException;

/**
 * Servicio para manejo de refresh tokens con: - Rotación de tokens - Revocación
 * de tokens - Verificación de expiración - Manejo de concurrencia
 */
@Service
public class RefreshTokenService {
    private static final String USER_NOT_FOUND = "Usuario no encontrado con ID: ";
    private static final String TOKEN_REVOKED_LOG = "Token revocado: {}";
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    @Value("${jwt.refresh-expiration-ms}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException(USER_NOT_FOUND + userId));
    
    revokeAllUserTokens(userId);
    
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setUser(user);
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    refreshToken.setUsed(false);
    
    RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
    logger.info("Nuevo refresh token creado para usuario: {}", userId);
    
    return savedToken;
    }

    // Añadir estos métodos a tu servicio existente:
    public RefreshToken rotateRefreshToken(String oldRefreshToken) {
        // 1. Validar token antiguo
        RefreshToken oldToken = verifyExpiration(
            findByToken(oldRefreshToken)
        );

        // 2. Marcar como usado y eliminar
        oldToken.setUsed(true);
        refreshTokenRepository.save(oldToken);
        logger.info("Refresh token marcado como usado: {}", oldToken.getId());

        // 3. Eliminar todos los tokens del usuario (opcional, depende de tu política)
        revokeAllUserTokens(oldToken.getUser().getId());

        // 4. Crear nuevo token
        return createRefreshToken(oldToken.getUser().getId());
    }

    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token).orElseThrow(() -> new TokenRefreshException(token, "Refresh token no encontrado"));
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().isBefore(Instant.now())) {
        refreshTokenRepository.delete(token);
        logger.warn(TOKEN_REVOKED_LOG, token.getToken());
        throw new TokenRefreshException(token.getToken(), "Token expirado");
    }
    
    if (token.isUsed()) {
        refreshTokenRepository.delete(token);
        logger.warn(TOKEN_REVOKED_LOG, token.getToken());
        throw new TokenRefreshException(token.getToken(), "Token ya utilizado");
    }
    
    return token;
    }

    public Optional<RefreshToken> findByUser(String username) {
        return refreshTokenRepository.findByUser(username);
    }

    @Transactional
    public void revokeByToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshToken -> {
            refreshTokenRepository.delete(refreshToken);
            logger.info("Token revocado: {}", token);
        });
    }

    @Transactional
    public void revokeAllUserTokens(Long userId) {
        refreshTokenRepository.deleteAllByUserId(userId);
        logger.info("Todos los refresh tokens revocados para usuario ID: {}", userId);
    }

    public boolean isTokenRevoked(String token) {
        return !refreshTokenRepository.existsByToken(token);
    }

    public boolean isRefreshTokenValid(Long userId) {
    Optional<RefreshToken> refreshToken = refreshTokenRepository.findByUserId(userId);
    return refreshToken.isPresent() && 
           !refreshToken.get().isUsed() && 
           refreshToken.get().getExpiryDate().isAfter(Instant.now());
}
}
