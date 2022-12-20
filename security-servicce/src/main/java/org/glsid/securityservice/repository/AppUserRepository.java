package org.glsid.securityservice.repository;

import org.glsid.securityservice.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

//@RepositoryRestResource
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(final String username);
}
