
package org.familysearch.cmp.authorization;

import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.AuthorizationFilter;
import org.familysearch.engage.foundation.security.AuthorizationFilterChain;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.familysearch.identity.api.IdentityService;
import org.familysearch.identity.api.PermissionSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;


/**
 * {@link AuthorizationFilter} to check permissions by using CASC.
 *
 * (Shamelessly stolen from the units project)
 */
public class CASAuthorizationFilter implements AuthorizationFilter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private FoundationSecurityManager foundationSecurityManager;
    private IdentityService identityService;
    private List<String> handledPermissions = new ArrayList<>();
    private String defaultCasAuthorizationContext;


    @Required
    public void setFoundationSecurityManager( FoundationSecurityManager foundationSecurityManager ) {
        this.foundationSecurityManager = foundationSecurityManager;
    }

    @Required
    public void setIdentityService(IdentityService identityService) {
    this.identityService = identityService;
  }


    @Required
    public void setHandledPermissions(List<String> handledPermissions) {
    this.handledPermissions = handledPermissions;
  }


    /**
     * Default CAS authorization context to use if one does not exist in
     * the {@link AuthorizationContext}.
     *
     * @param defaultCasAuthorizationContext A default CAS authorization context.
     */
    @Required
    public void setDefaultCasAuthorizationContext(String defaultCasAuthorizationContext) {
        this.defaultCasAuthorizationContext = defaultCasAuthorizationContext;
    }


    @Override
    public boolean isAuthorized(AuthorizationFilterChain filterChain, AuthorizationContext context) {

        String sessionID = foundationSecurityManager.authenticatedSessionID();

        if ( isAuthenticated(sessionID) ) {

            List<String> casPermissions = new ArrayList<>();
            for (String handledPermission : handledPermissions) {
                if (context.getPermissionNames().contains(handledPermission)) {
                    casPermissions.add(handledPermission);
                }
            }

            if ( hasPermissionsToRequest(casPermissions) ) {
                try {
                    String casContext = defaultCasAuthorizationContext;
                    if (hasCASContext(context)) {
                        casContext = context.get(AuthorizationContext.KEY_CAS_CONTEXT, String.class);
                    }

//          final String cisId = foundationSecurityManager.authenticatedUserID();
//          final String proxyCisId = foundationSecurityManager.proxyUserID();
//
//          Future<PermissionSet> future = identityService.isAuthorizedCached(sessionID, casContext,
//                                                                            cisId, proxyCisId, casPermissions);

                    Future<PermissionSet> future;
                    future = identityService.isAuthorized( sessionID, casContext, casPermissions );

                    PermissionSet permissionSet = future.get();

                    for (String authorized : permissionSet.getAuthorizedPermissions()) {
                        if (casPermissions.contains(authorized)) {
                            return true;
                        }
                    }
                }
                catch( RuntimeException | InterruptedException | ExecutionException ex ) {
                    // log but delegate to the chain
                    logger.debug( "isAuthorized Exception", ex );
                    logger.error("Exception resolving CAS permissions: {}", ex.getMessage() );
                }
            }
        }

        return filterChain.isAuthorized(context);
    }


    private boolean hasCASContext(AuthorizationContext context) {
        return context.get(AuthorizationContext.KEY_CAS_CONTEXT) != null;
    }


    private boolean hasPermissionsToRequest(List<String> casPermissions) {
        return !casPermissions.isEmpty();
    }


    private boolean isAuthenticated(String sessionID) {
        return sessionID != null;
    }


}

