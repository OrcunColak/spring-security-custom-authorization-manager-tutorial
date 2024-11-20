package com.colak.springtutorial.config;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

public class RoleAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final String requiredRole;

    public RoleAuthorizationManager(String requiredRole) {
        this.requiredRole = requiredRole;
    }

    // This is the core evaluation method, which determines whether a request should be authorized.
    // It returns an AuthorizationDecision, which is either true (grant access) or false (deny access) based on the
    // provided authentication and context.
    @Override
    public AuthorizationDecision check(Supplier<Authentication> supplier, RequestAuthorizationContext context) {
        Authentication authentication = supplier.get();
        boolean hasRole = authentication.getAuthorities()
                .stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(requiredRole));
        return new AuthorizationDecision(hasRole);
    }

}