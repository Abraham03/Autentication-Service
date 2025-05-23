package com.GestionRemodelacion.gestion.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.GestionRemodelacion.gestion.model.Permission;

@Repository
public interface  PermissionRepository extends JpaRepository<Permission, Long>{

    Permission findByName(String name);

}
