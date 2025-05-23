package com.GestionRemodelacion.gestion.controller.auth;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.GestionRemodelacion.gestion.dto.request.LoginRequest;
import com.GestionRemodelacion.gestion.dto.request.RefreshTokenRequest;
import com.GestionRemodelacion.gestion.dto.request.SignupRequest;
import com.GestionRemodelacion.gestion.dto.response.ApiResponse;
import com.GestionRemodelacion.gestion.dto.response.AuthResponse;
import com.GestionRemodelacion.gestion.security.jwt.JwtUtils;
import com.GestionRemodelacion.gestion.service.auth.AuthService;
import com.GestionRemodelacion.gestion.service.user.UserService;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

/**
 * Controlador de autenticación con: - Documentación Swagger - Validación de
 * entrada - Manejo centralizado de errores - Respuestas estandarizadas
 */
@Tag(name = "Authentication", description = "API para manejo de autenticación")
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final UserService userService;
    private final AuthService authService;
    private final JwtUtils jwtUtils;

    public AuthController(UserService userService, AuthService authService, JwtUtils jwtUtils) {
        this.userService = userService;
        this.authService = authService;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.authenticate(loginRequest));
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> registerUser(
            @Valid @RequestBody SignupRequest signUpRequest) {

        // Asignar ROLE_USER por defecto si no se especifica
        if (signUpRequest.getRoles() == null || signUpRequest.getRoles().isEmpty()) {
            signUpRequest.setRoles(Set.of("ROLE_USER"));
        }

        userService.createUser(signUpRequest);
        return ResponseEntity.status(201).body(
                new ApiResponse<>(201, "Usuario registrado exitosamente", null));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        LOGGER.debug("Intento de refresh token con token: {}",
                request.getRefreshToken().substring(request.getRefreshToken().length() - 6));

        AuthResponse response = authService.refreshToken(request);

        LOGGER.info("Refresh token exitoso para usuario: {}",
                jwtUtils.getUserNameFromJwtToken(response.getToken()));

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7); // Eliminar "Bearer "
        authService.logout(token);
        return ResponseEntity.ok(
                new ApiResponse<>(200, "Sesión cerrada exitosamente", null));
    }
}
