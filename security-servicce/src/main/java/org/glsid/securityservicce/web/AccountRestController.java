package org.glsid.securityservicce.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.glsid.securityservicce.JWTUtil;
import org.glsid.securityservicce.entities.AppRole;
import org.glsid.securityservicce.entities.AppUser;
import org.glsid.securityservicce.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAnyAuthority('USER')")
    public List<AppUser> appUserList(){
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    public AppUser addUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    public AppRole addRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }

    @GetMapping(path = "/profil")
    public AppUser profil(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authToken=request.getHeader(JWTUtil.AUTH_HEADER);
        if(authToken!=null & authToken.startsWith(JWTUtil.PREFIX)){
            try{
                String refreshToken=authToken.substring(JWTUtil.PREFIX.length());
                Algorithm algorithm=Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT=jwtVerifier.verify(refreshToken);
                String username=decodedJWT.getSubject();
                AppUser appUser=accountService.loadUserByUsername(username);
                String accessToken= JWT.create().withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN)) // 5 minutes
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(ga->ga.getRoleName())
                                .collect(Collectors.toList())).sign(algorithm);
                Map<String,String> idToken=new HashMap<>();
                idToken.put("access-token",accessToken);
                idToken.put("refresh-token",refreshToken);
                //response.setHeader("Authorization",accessToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);

            }catch (Exception e){
                throw e;
            }
        }
        else{
            throw new RuntimeException("Refresh token invalid!");
        }
    }
}

@Data
class RoleUserForm{
    private String username;
    private String roleName;
}
