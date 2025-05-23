package com.GestionRemodelacion.gestion.service.user;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.GestionRemodelacion.gestion.dto.request.SignupRequest;
import com.GestionRemodelacion.gestion.model.Role;
import com.GestionRemodelacion.gestion.model.User;
import com.GestionRemodelacion.gestion.repository.RoleRepository;
import com.GestionRemodelacion.gestion.repository.UserRepository;

/**
 * Servicio para manejar la lógica de negocio relacionada con usuarios.
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User createUser(SignupRequest signUpRequest) {
        // Crear nuevo usuario
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        // Asignar roles
        Set<Role> roles = new HashSet<>();
        
        if (signUpRequest.getRoles() == null || signUpRequest.getRoles().isEmpty()) {
            // Asignar rol por defecto (USER)
            Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Error: Rol USER no encontrado."));
            roles.add(userRole);
        } else {
            // Asignar roles especificados en la solicitud
            signUpRequest.getRoles().forEach(role -> {
                Role foundRole = roleRepository.findByName(role)
                    .orElseThrow(() -> new RuntimeException("Error: Rol " + role + " no encontrado."));
                roles.add(foundRole);
            });
        }

        user.setRoles(roles);
        return userRepository.save(user);
    }

    /**
     * Guarda un nuevo usuario en la base de datos.
     *
     * @param user Usuario a guardar
     * @return Usuario guardado
     */
    @Transactional
    public User save(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    /**
     * Busca un usuario por su nombre de usuario.
     *
     * @param username Nombre de usuario
     * @return Optional con el usuario encontrado
     */
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Busca un usuario por su id de usuario.
     *
     * @param id Nombre de usuario
     * @return Optional con el usuario encontrado
     */
    @Transactional(readOnly = true)
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    /**
     * Verifica si existe un usuario con el nombre de usuario dado.
     *
     * @param username Nombre de usuario
     * @return true si existe, false en caso contrario
     */
    @Transactional(readOnly = true)
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * Asigna roles a un usuario.
     *
     * @param userId ID del usuario
     * @param roles Conjunto de roles a asignar
     * @return Usuario actualizado
     */
    @Transactional
    public User assignRolesToUser(Long userId, Set<Role> roles) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        user.getRoles().addAll(roles);
        return userRepository.save(user);
    }

    /**
     * Obtiene todos los usuarios.
     *
     * @return Lista de usuarios
     */
    @Transactional(readOnly = true)
    public List<User> findAll() {
        return userRepository.findAll();
    }

}
