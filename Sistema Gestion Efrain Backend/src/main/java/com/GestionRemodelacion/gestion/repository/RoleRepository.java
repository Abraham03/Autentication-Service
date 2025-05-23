package com.GestionRemodelacion.gestion.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.GestionRemodelacion.gestion.model.Role;

/**
 * Repositorio para la entidad Role que proporciona operaciones CRUD
 * y consultas personalizadas relacionadas con roles.
 */
@Repository
public interface  RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);

    Optional<Role> findByName(Role name);
    
    Boolean existsByName(String name);

}
