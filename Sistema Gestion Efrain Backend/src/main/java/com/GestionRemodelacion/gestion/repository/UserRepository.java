package com.GestionRemodelacion.gestion.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.GestionRemodelacion.gestion.model.User;

/**
 * Repositorio para la entidad User que proporciona operaciones CRUD
 * y consultas personalizadas relacionadas con usuarios.
 */
@Repository

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);    
    Boolean existsByUsername(String username);
    }
