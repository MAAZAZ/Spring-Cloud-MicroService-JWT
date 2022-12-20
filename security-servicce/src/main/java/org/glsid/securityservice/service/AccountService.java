package org.glsid.securityservice.service;

import org.glsid.securityservice.entities.AppRole;
import org.glsid.securityservice.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(final AppUser appUser);
    AppRole addNewRole(final AppRole appRole);
    void addRoleToUser(final String username, final String roleName);
    AppUser loadUserByUsername(final String username);
    List<AppUser> listUsers();
}

