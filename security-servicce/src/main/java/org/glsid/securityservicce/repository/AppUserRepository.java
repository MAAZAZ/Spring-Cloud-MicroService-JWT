package org.glsid.securityservicce.repository;

import org.glsid.securityservicce.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

//@RepositoryRestResource
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
