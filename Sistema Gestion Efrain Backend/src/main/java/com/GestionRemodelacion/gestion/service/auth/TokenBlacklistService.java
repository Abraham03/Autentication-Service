package com.GestionRemodelacion.gestion.service.auth;

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.GestionRemodelacion.gestion.security.jwt.JwtUtils;

/**
 * Servicio para manejar tokens revocados (blacklist).
 * 
 * Usado por:
 * - JwtAuthFilter para verificar tokens revocados
 * - AuthService durante el logout
 * 
 * Características:
 * - Almacenamiento en memoria con ConcurrentHashMap para thread-safety
 * - Limpieza periódica de tokens expirados
 * - Métodos para agregar y verificar tokens
 */
@Service
public class TokenBlacklistService {
    private static final Logger logger = LoggerFactory.getLogger(TokenBlacklistService.class);
    private final ConcurrentMap<String, Instant> blacklist = new ConcurrentHashMap<>();
    private final JwtUtils jwtUtils;

    public TokenBlacklistService(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    /**
     * Añade un token a la blacklist con su fecha de expiración
     * 
     * Área crítica: Manejo concurrente del mapa
     */
public void blacklistToken(String token, Instant expiryDate) {
    if (jwtUtils.validateJwtToken(token)) {
        blacklist.put(token, expiryDate);
        logger.debug("Token añadido a blacklist: {}", token.substring(token.length() - 6));
    }
}
    /**
     * Verifica si un token está en la blacklist
     * 
     * Área crítica: Verificación atómica de existencia y expiración
     */
    public boolean isBlacklisted(String token) {
        Instant expiry = blacklist.get(token);
        return expiry != null && expiry.isAfter(Instant.now());
    }
    

    /**
     * Limpieza programada de tokens expirados
     * 
     * Se ejecuta cada hora para mantener el mapa limpio
     */
@Scheduled(fixedRate = 3600000) // Cada hora
public void cleanExpiredTokens() {
    Instant now = Instant.now();
    blacklist.entrySet().removeIf(entry -> 
        jwtUtils.getExpirationDateFromToken(entry.getKey()).before(Date.from(now))
    );
}

    public void removeFromBlacklist(String token) {
        blacklist.remove(token);
    }    

}