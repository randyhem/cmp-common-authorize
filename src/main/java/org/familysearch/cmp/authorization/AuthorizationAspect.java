
package org.familysearch.cmp.authorization;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;

import org.familysearch.cmp.authorization.exception.UnauthenticatedException;
import org.familysearch.cmp.authorization.exception.UnauthorizedException;
import org.familysearch.cmp.authorization.util.StringUtils;
import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


/**
 * An Aspect that targets methods annotated with @PermissionRequired.
 * This aspect builds an AuthorizationContext instance and delegates
 * to {@link FoundationSecurityManager} instance to determine if the request
 * is authorized.
 *
 * (Shamelessly stolen from the units project)
 */
@Aspect
@Component
public class AuthorizationAspect {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationAspect.class);



    @Autowired
    private FoundationSecurityManager securityManager;


    @Pointcut(value = "execution(@PermissionRequired * *(..)) && @annotation(permission)", argNames = "permission")
    public void permissionRequired(PermissionRequired permission) {
    }


    @Before(value = "permissionRequired(permission) && !within(AuthorizationAspect)", argNames = "permission")
    public void doAccessCheck(PermissionRequired permission) {

        final AuthorizationContext context = createContext(permission);

        if ( ! securityManager.isAuthorized(context)) {
            LOGGER.info( "Authorization denied; required permissions={}, casContext={}",
                          context.getPermissionNames(),
                          context.get( AuthorizationContext.KEY_CAS_CONTEXT ) );
            throw new UnauthorizedException();
        }
    }


    /**
     * Create the AuthorizationContext by obtaining the required permissions from the annotation.
     *
     * @param permission annotation on the method containing the required set of permissions
     * @return an AuthorizationContext
     *
     * @throws UnauthenticatedException if the session ID is not provided or the session ID is the string "null".
     */
    private AuthorizationContext createContext(PermissionRequired permission) {

        final AuthorizationContext authContext = new AuthorizationContext(permission.value());

        final String sessionId = securityManager.authenticatedSessionID();

        if ( StringUtils.isNullorEmpty( sessionId ) ) {
            throw new UnauthenticatedException("User not authenticated. No session ID.");
        }

        // Do this only if the endpoint requires a session read to get a different CAS context.
        // do this after we know we have a session since this will force a read of the session.
        // this is used by the CASAuthorizationFilter for elevated privilege checking.
        if ( permission.requireCheckSessionCasContext() ) {
            authContext.casContext( securityManager.casContext() );
        }

        return authContext;
    }


}

