
/*
 * (c) 2018 by Intellectual Reserve, Inc. All rights reserved.
 */

package org.familysearch.cmp.authorization;

import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.AuthorizationFilter;
import org.familysearch.engage.foundation.security.AuthorizationFilterChain;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.familysearch.identity.api.IdentityService;
import org.familysearch.identity.api.PermissionSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import jersey.repackaged.com.google.common.base.Preconditions;


/**
 * {@link AuthorizationFilter} to check permissions by using CAS.
 *
 * (Shamelessly stolen from the units project)
 */
public class CASAuthorizationFilter implements AuthorizationFilter {

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private static final String NULL_REQUIRED_ARG = "No %s object provided (null)";


    final private FoundationSecurityManager foundationSecurityManager;
    final private IdentityService           identityService;
    final private Set<String>               handledPermissions;
    final private String                    defaultCasAuthorizationContext;


    public CASAuthorizationFilter( FoundationSecurityManager    securityMgr,
                                   IdentityService              identService,
                                   String                       casAuthContext,
                                   Set<String>                  validPermissions ) {

        Preconditions.checkArgument( securityMgr != null,
                                     String.format( NULL_REQUIRED_ARG, "FoundationSecurityManager" ) );
        Preconditions.checkArgument( identService != null,
                                     String.format( NULL_REQUIRED_ARG, "IdentityService" ) );
        Preconditions.checkArgument( casAuthContext != null,
                                     String.format( NULL_REQUIRED_ARG, "CasAuthorizationContext" ) );
        Preconditions.checkArgument( validPermissions != null,
                                     String.format( NULL_REQUIRED_ARG, "Set<Permissions>" ) );
        Preconditions.checkArgument( ! validPermissions.isEmpty(),
                                     "Empty expected permissions set provided" );

        foundationSecurityManager = securityMgr;
        identityService = identService;
        defaultCasAuthorizationContext = casAuthContext;
        handledPermissions = validPermissions;
    }


    @Override
    public boolean isAuthorized(AuthorizationFilterChain filterChain, AuthorizationContext context) {

        String sessionID = foundationSecurityManager.authenticatedSessionID();

        if ( sessionID != null ) {

            List<String> casPermissions = new ArrayList<>();
            for ( String handledPermission : handledPermissions ) {
                if ( context.getPermissionNames().contains(handledPermission) ) {
                    casPermissions.add( handledPermission );
                }
            }

            if ( hasPermissionsToRequest( casPermissions ) ) {
                try {
                    String casContext = defaultCasAuthorizationContext;
                    if ( hasCASContext(context) ) {
                        casContext = context.get( AuthorizationContext.KEY_CAS_CONTEXT, String.class );
                    }

                    Future<PermissionSet> future;
                    future = identityService.isAuthorized( sessionID, casContext, casPermissions );

                    PermissionSet permissionSet = future.get();

                    for ( String authorized : permissionSet.getAuthorizedPermissions() ) {
                        if ( casPermissions.contains(authorized) ) {
                            return true;
                        }
                    }
                }
                catch( RuntimeException | InterruptedException | ExecutionException ex ) {
                    // log but delegate to the chain
                    logger.debug( "isAuthorized Exception", ex );
                    logger.error( "Exception resolving CAS permissions: {}", ex.getMessage() );
                }
            }
        }

        return filterChain.isAuthorized(context);
    }


    private boolean hasCASContext( AuthorizationContext context ) {
        return context.get( AuthorizationContext.KEY_CAS_CONTEXT ) != null;
    }


    private boolean hasPermissionsToRequest( List<String> casPermissions ) {
        return !casPermissions.isEmpty();
    }


}

