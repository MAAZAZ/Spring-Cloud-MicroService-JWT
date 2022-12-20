package org.glsid.securityservice;

import org.glsid.securityservice.entities.AppRole;
import org.glsid.securityservice.entities.AppUser;
import org.glsid.securityservice.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityServiceApplication.class, args);
    }

    @Bean
    CommandLineRunner start(final AccountService accountService, final RepositoryRestConfiguration repositoryRestConfiguration){
        return args ->  {
            // repositoryRestConfiguration.exposeIdsFor(AppRole.class);
            // repositoryRestConfiguration.exposeIdsFor(AppUser.class);
            // data for test only
            accountService.addNewRole( new AppRole(null,"USER"));
            accountService.addNewRole( new AppRole(null,"ADMIN"));
            accountService.addNewRole( new AppRole(null,"CUSTOMER_MANAGER"));
            accountService.addNewRole( new AppRole(null,"PRODUCT_MANAGER"));
            accountService.addNewRole( new AppRole(null,"BILLS_MANAGER"));

            accountService.addNewUser(new AppUser(null,"user1","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user2","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user3","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user4","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"admin","1234",new ArrayList<>()));
            accountService.addRoleToUser("user1","USER");
            accountService.addRoleToUser("admin","ADMIN");
            accountService.addRoleToUser("admin","USER");
            accountService.addRoleToUser("user2","USER");
            accountService.addRoleToUser("user2","CUSTOMER_MANAGER");
            accountService.addRoleToUser("user3","USER");
            accountService.addRoleToUser("user3","PRODUCT_MANAGER");
            accountService.addRoleToUser("user4","USER");
            accountService.addRoleToUser("user4","BILLS_MANAGER");
        };
    }
}
