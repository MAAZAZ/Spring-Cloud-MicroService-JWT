package org.glsid.securityservice.repository;

import org.glsid.securityservice.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

//@RepositoryRestResource
public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(final String roleName);
}

