package com.GestionRemodelacion.gestion.service.impl;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.GestionRemodelacion.gestion.model.User;

/**
 * Implementación personalizada de UserDetails para Spring Security.
 * 
 * Usado por:
 * - Spring Security para la autenticación y autorización
 * - JwtAuthFilter para construir el contexto de seguridad
 * - AuthService para generar tokens JWT
 * 
 * Contiene:
 * - Información básica del usuario (id, username, password)
 * - Roles convertidos a autoridades de Spring Security
 * - Métodos para verificar estado de la cuenta
 */
public class UserDetailsImpl implements UserDetails {
    private final Long id;
    private final String username;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;

    // Constructor principal
    public UserDetailsImpl(Long id, String username, String password, 
                         Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    /**
     * Método factory para construir UserDetailsImpl desde un User
     * 
     * Área crítica: Conversión de roles a autoridades
     * - Asegura que cada rol tenga el prefijo "ROLE_" si no lo tiene
     */
    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(
                    role.getName().startsWith("ROLE_") ? 
                    role.getName() : "ROLE_" + role.getName()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                authorities);
    }

    // Getters y métodos requeridos por UserDetails
    public Long getId() { return id; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() { return password; }

    @Override
    public String getUsername() { return username; }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}