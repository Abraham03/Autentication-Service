package com.GestionRemodelacion.gestion.service.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.GestionRemodelacion.gestion.model.User;
import com.GestionRemodelacion.gestion.security.jwt.JwtUtils;
import com.GestionRemodelacion.gestion.service.user.UserService;

/**
 * Servicio para manejar la autenticación JWT y la generación de tokens.
 */
@Service
public class JwtService {
    
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserService userService;

    public JwtService(AuthenticationManager authenticationManager, JwtUtils jwtUtils, UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
    }

        /**
     * Autentica un usuario y genera un token JWT.
     * @param username Nombre de usuario
     * @param password Contraseña
     * @return Token JWT generado
     */

         public String authenticateAndGenerateToken(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password));
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return jwtUtils.generateJwtToken(authentication);
    }

    /**
     * Obtiene el usuario actualmente autenticado.
     * @return User autenticado
     */
    public User getAuthenticatedUser() {
        String username = SecurityContextHolder.getContext()
            .getAuthentication()
            .getName();
        
        return userService.findByUsername(username)
            .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
    }

}
