package com.GestionRemodelacion.gestion.security.jwt;

import java.io.IOException;
import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.util.concurrent.RateLimiter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro para limitación de tasa de peticiones.
 * 
 * Usado por:
 * - SecurityConfig como primer filtro en la cadena
 * 
 * Características:
 * - Limita a 100 peticiones por segundo (ajustable)
 * - Respuesta 429 Too Many Requests cuando se excede
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {
    private final RateLimiter globalLimiter = RateLimiter.create(100); // Límite global
    private final Map<String, RateLimiter> endpointLimiters = Map.of(
        "/api/auth/login", RateLimiter.create(5),  // 5 peticiones/segundo para login
        "/api/auth/refresh", RateLimiter.create(10) // 10 para refresh
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) 
        throws ServletException, IOException {
        
        String path = request.getRequestURI();
        RateLimiter limiter = endpointLimiters.getOrDefault(path, globalLimiter);

        if (!limiter.tryAcquire()) {
            response.setHeader("Retry-After", "60"); // Segundos
            response.sendError(429, "Too Many Requests");
            return;
        }
        filterChain.doFilter(request, response);
    }
}