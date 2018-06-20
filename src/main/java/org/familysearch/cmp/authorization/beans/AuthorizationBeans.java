
/*
 * (c) 2018 by Intellectual Reserve, Inc. All rights reserved.
 */

package org.familysearch.cmp.authorization.beans;

import com.sun.jersey.api.client.Client;

import jersey.repackaged.com.google.common.base.Preconditions;
import org.familysearch.cmp.authorization.ValidSessionOnlyAuthorizationFilter;
import org.familysearch.cmp.authorization.CASAuthorizationFilter;
import org.familysearch.cmp.authorization.permissions.CmpPermission;
import org.familysearch.engage.foundation.security.AuthorizationFilterChain;
import org.familysearch.engage.foundation.security.CISCASClientCachingSecurityManager;
//import org.familysearch.engage.foundation.security.CISCASClientSecurityManager;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.familysearch.identity.api.IdentityService;
import org.familysearch.identity.api.impl.IdentityContextFilter;
import org.familysearch.identity.api.impl.IdentityServiceWithBindingRegisterImpl;

import org.familysearch.paas.binding.register.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
//import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.Arrays.asList;
import static org.familysearch.identity.api.impl.IdentityServiceImpl.createDefaultClientConfig;
import static org.familysearch.identity.api.impl.IdentityServiceImpl.createDefaultClientHandler;

/**
 * Spring configuration for all security related beans
 */
@Configuration
@EnableAspectJAutoProxy
public class AuthorizationBeans {

    private final Logger logger = LoggerFactory.getLogger( getClass());

    private static final String CIS_URI = String.format( "%s://cis-public-api.cis.ident.service", ServiceLocationUri.SCHEME );
    private static final String CAS_URI = String.format( "%s://cas-public-api.cas.ident.service", ServiceLocationUri.SCHEME );


    @Bean
    @Autowired
    public FoundationSecurityManager securityManager( @Value( "${cmp.auth.session.context}" )       // "UserMessaging"
                                                        String                  authContextSessionValue,
                                                      @Value( "${cmp.auth.session.permission" )     // CmpPermission.SessionRequired
                                                        String                  validSessionPermissionName,
                                                      @Value( "${cmp.auth.valid.cas.roles" )
                                                         List<CmpPermission>    validCasPermissions,
                                                      @Value( "${cmp.auth.cas.context" )            // "FSMessagingDefaultContext"
                                                         String                 casContextName) {

        Preconditions.checkArgument( validSessionPermissionName != null,
                                     "No Session-Permission-Name provided (null)" );
        Preconditions.checkArgument( (validCasPermissions != null) && (! validCasPermissions.isEmpty()),
                                     "Invalid CAS CmpPermission List provided" );

        final CISCASClientCachingSecurityManager securityManager = new CISCASClientCachingSecurityManager();

        securityManager.setIdentityService( identityService() );
//        securityManager.setAuthContextSessionValueName( "UserMessaging" );
        securityManager.setAuthContextSessionValueName( authContextSessionValue );
        securityManager.setSessionCookieAllowed( false );
        securityManager.setQueryParameterAllowed( true );
        securityManager.setSessionIdentityPreferred( true );

        securityManager.setAuthorizationFilterChainPrototype( authorizationFilterChain( securityManager, validSessionPermissionName, validCasPermissions, casContextName ) );

        logger.info( "FoundationSecurityManager bean initialized ..." );
        return( securityManager );
    }


    @Bean
    public IdentityService identityService() {

        IdentityService idService;
        ServiceLocatorConfig serviceLocatorConfig = new ServiceLocatorConfig();
        ServiceLocator serviceLocator = new ServiceLocator( serviceLocatorConfig );
        ServiceLocationResolver serviceLocationResolver = new DefaultServiceLocationResolver( serviceLocator );

        // NOTE: This is deprecated, but we really are supposed to be doing something called SKID, which we don't know how to do right now
        Client client = new Client( createDefaultClientHandler(), createDefaultClientConfig() );

        //    return new IdentityServiceWithBindingRegisterImpl(serviceLocationResolver, CIS_URI, CAS_URI, CASC_URI, null, client);
        idService = new IdentityServiceWithBindingRegisterImpl( serviceLocationResolver, CIS_URI, CAS_URI,
                                                             null, null, client );

        logger.info( "IdentityService bean initialized ..." );
        return( idService );
    }


//    @Bean
    public AuthorizationFilterChain authorizationFilterChain( FoundationSecurityManager    fsMgr,
                                                              String                       sessionPermName,
                                                              List<CmpPermission>          validCasRoleLst,
                                                              String                       casAuthContextID ) {
        final AuthorizationFilterChain authorizationFilterChain = new AuthorizationFilterChain();
        authorizationFilterChain.setFilters( asList( sessionOnlyAuthorizationFilter( fsMgr, sessionPermName ),
                                                     cascAuthorizationFilter( fsMgr, validCasRoleLst, casAuthContextID ) ) );

        logger.info( "AuthorizationFilterChain initialized ..." );
        return authorizationFilterChain;
    }


//    @Bean
    public ValidSessionOnlyAuthorizationFilter sessionOnlyAuthorizationFilter( FoundationSecurityManager    fsMgr,
                                                                               String                       sessionPermissionName ) {

        ValidSessionOnlyAuthorizationFilter sessionFilter;
        sessionFilter = new ValidSessionOnlyAuthorizationFilter( fsMgr, sessionPermissionName );

        logger.info( "CASAuthorizationFilter initialized ..." );
        return( sessionFilter );
    }


//    @Bean
    public CASAuthorizationFilter cascAuthorizationFilter( FoundationSecurityManager    fsMgr,
                                                           List<CmpPermission>          validCasRoleLst,
                                                           String                       casAuthContextID ) {

        CASAuthorizationFilter  casFilter;

        Set<String> validCasRoles = new HashSet<>();
        for( CmpPermission nxtPermission : validCasRoleLst ) {
            validCasRoles.add( nxtPermission.name() );
        }

//        validCasRoles.add( CmpPermission.FSMessagingModifyThread.name() );
//        validCasRoles.add( CmpPermission.FSMessagingAdminApiViewThread.name() );
//        validCasRoles.add( CmpPermission.FSMessagingAdminApiModifyThread.name() );

        casFilter = new CASAuthorizationFilter( fsMgr,
                                                identityService(),
                                                casAuthContextID,  // "FSMessagingDefaultContext",
                                                validCasRoles );

        logger.info( "CASAuthorizationFilter initialized ..." );
        return( casFilter );

//        final CASCAuthorizationFilter authorizationFilter = new CASCAuthorizationFilter();
        //        authorizationFilter.setDefaultCasAuthorizationContext( "FSMessagingDefaultContext" );
//        authorizationFilter.setHandledPermissions( Arrays.asList(
//            FsMessagesPermission.FSMessagingAdminApiViewThread.getName(),
//            FsMessagesPermission.FSMessagingAdminApiModifyThread.getName() ) );
//        authorizationFilter.setIdentityService( identityService() );
//         don't set the security manager here. Circular dependency (see securityManager())
//        return authorizationFilter;
    }


//    @Bean
//    public IdentityContextFilter identityContextFilter() {
//        return new IdentityContextFilter();
//    }


}

