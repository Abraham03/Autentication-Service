package com.GestionRemodelacion.gestion.service.role;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.GestionRemodelacion.gestion.model.Role;
import com.GestionRemodelacion.gestion.repository.RoleRepository;

@Service
public class RoleService {

    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public List<Role> findAll() {
        return roleRepository.findAll();
    }

    public Role save(Role role) {
        return roleRepository.save(role);
    }

    public Role update(Long id, Role role) {
        role.setId(id);
        return roleRepository.save(role);
    }

    public Optional<Role> findByName(String name) {
        return roleRepository.findByName(name);
    }

    

}
