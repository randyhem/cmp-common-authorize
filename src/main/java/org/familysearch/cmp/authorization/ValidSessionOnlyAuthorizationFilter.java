
package org.familysearch.cmp.authorization;

import org.familysearch.cmp.authorization.util.StringUtils;
import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.AuthorizationFilter;
import org.familysearch.engage.foundation.security.AuthorizationFilterChain;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.context.annotation.Lazy;


/**
 * An {@link AuthorizationFilter} that always grants permission if there is a session provided.
 * <p>
 * (Shamelessly stolen from the units project)
 */
public class ValidSessionOnlyAuthorizationFilter implements AuthorizationFilter {


    @Autowired
    @Lazy
    private FoundationSecurityManager foundationSecurityManager;

    private String sessionRequiredPermissionName;


    @Required
    public void setFoundationSecurityManager(FoundationSecurityManager foundationSecurityManager) {
        this.foundationSecurityManager = foundationSecurityManager;
    }


    @Required
    public void setSessionRequiredPermissionName(String sessionRequiredPermissionName) {
        this.sessionRequiredPermissionName = sessionRequiredPermissionName;
    }


    @Override
    public boolean isAuthorized(AuthorizationFilterChain filterChain, AuthorizationContext context) {
        /*
            The first step of any authorization is to establish identity.  Throw an UnauthenticatedException if the request has
            no sessionId or if the sessionId has expired.  This will map to a 401 response and the request will not be further
            processed by any other authorization filters (because no authorization can be done without first authenticating).
            NOTE: This filter should be registered first in the filter chain so that unauthenticated requests never reach other
            filters.
        */
        final String authenticatedUserID = foundationSecurityManager.authenticatedUserID();
        if ( StringUtils.isNullorEmpty( authenticatedUserID ) ) {
            throw new UnauthenticatedException("The request is not authenticated with a valid session token");
        }

        // Now that the request has been verified to be authenticated, check the context to see which permissions are required
        if (context.getPermissionNames().contains(sessionRequiredPermissionName)) {
            // Authentication alone is sufficient to authorize this request, return true
            return true;
        }
        else {
            // The permission required is not handled by this class, defer to the next authorization filter in the chain.
            return filterChain.isAuthorized(context);
        }
    }


}

