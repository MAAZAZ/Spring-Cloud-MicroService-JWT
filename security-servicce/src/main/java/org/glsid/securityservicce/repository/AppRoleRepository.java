package org.glsid.securityservicce.repository;

import org.glsid.securityservicce.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

//@RepositoryRestResource
public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(String roleName);
}

