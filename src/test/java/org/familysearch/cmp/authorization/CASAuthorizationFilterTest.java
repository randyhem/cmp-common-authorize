
/*
 * (c) 2018 by Intellectual Reserve, Inc. All rights reserved.
 */

package org.familysearch.cmp.authorization;

import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.AuthorizationFilterChain;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.familysearch.identity.api.IdentityService;
import org.familysearch.identity.api.PermissionSet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.familysearch.cmp.authorization.permissions.CmpMsgPermission.SessionRequired;
import static org.familysearch.cmp.authorization.permissions.CmpMsgPermission.FSMessagingAdminApiViewThread;

import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;



@SuppressWarnings("unchecked")
public class CASAuthorizationFilterTest {

    private static int  testCnt = 0;
    private static Lock forceSerialLock = new ReentrantLock();

    private static final String TEST_CAS_CONTEXT =      "[CAS context]";

    private static final String TEST_CIS_SESSION_ID =   "[CIS session ID]";



    @InjectMocks
    private CASAuthorizationFilter testCasFilter;

    @Mock
    private FoundationSecurityManager mockSecurityManager;

    @Mock
    private IdentityService mockIdentityService;

    @Mock
    private AuthorizationFilterChain mockFilterChain;

    @Mock
    private Future<PermissionSet> mockFuturePermissionSet;

    @Captor
    private ArgumentCaptor<List<String>> permissionsCaptor;

    private PermissionSet permissionSet;


    @Before
    public void setup()
        throws Exception {

        // Force sequential test execution by requiring acquisition to exclusive lock!
        forceSerialLock.lock();
        ++testCnt;

        MockitoAnnotations.initMocks( this );

        testCasFilter.setDefaultCasAuthorizationContext( TEST_CAS_CONTEXT );
        List<String>    permList = new ArrayList<>();
        permList.add( SessionRequired.name() );

        testCasFilter.setHandledPermissions( permList );

        Set<String> authorizedPermissions = new HashSet<>();
        Set<String> deniedPermissions = new HashSet<>();
        permissionSet = new PermissionSet( TEST_CAS_CONTEXT, authorizedPermissions, deniedPermissions );

        when( mockIdentityService.isAuthorized( anyString(), anyString(), anyList() ) )
            .thenReturn( mockFuturePermissionSet );

        when( mockFuturePermissionSet.get() ).thenReturn( permissionSet );

        System.out.println( String.format( "\nTest %d Setup", testCnt ) );
        System.out.flush();
    }


    @After
    public void teardown() {
        System.out.println( String.format("Test %d Teardown", testCnt) );
        System.out.flush();
        forceSerialLock.unlock();
    }



    @Test
    public void isAuthorized_unauthenticated_proceedsWithChain()
        throws Exception {

        System.out.println( "  Test IsAuthorized (Unauthenticated)" );

        when( mockSecurityManager.authenticatedSessionID() ).thenReturn( null );
        AuthorizationContext context = new AuthorizationContext( SessionRequired );

        assertThat( testCasFilter.isAuthorized( mockFilterChain, context ), equalTo( false ) );
        verify( mockFilterChain, times(1) ).isAuthorized( context );
    }


    @Test
    public void isAuthorized()
        throws Exception {

        System.out.println( "  Test IsAuthorized (CAS Match)" );

        permissionSet.getAuthorizedPermissions().add( SessionRequired.name() );

        when( mockSecurityManager.authenticatedSessionID() ).thenReturn( TEST_CIS_SESSION_ID );

        AuthorizationContext context = new AuthorizationContext( SessionRequired );

        boolean actual = testCasFilter.isAuthorized( mockFilterChain, context );
        assertThat( actual, is( true ) );
        verify( mockFilterChain, times(0) ).isAuthorized( context );
    }


    @Test
    public void isAuthorized_neither()
        throws Exception {

        System.out.println( "  Test IsAuthorized (No CAS Roles)" );
        when( mockSecurityManager.authenticatedSessionID() ).thenReturn( TEST_CIS_SESSION_ID );

        AuthorizationContext context = new AuthorizationContext( SessionRequired );

        boolean actual = testCasFilter.isAuthorized( mockFilterChain, context );

        assertThat( actual, is( false ) );
        verify( mockFilterChain ).isAuthorized( context );
        verify( mockIdentityService )
            .isAuthorized( eq( TEST_CIS_SESSION_ID ), eq( TEST_CAS_CONTEXT ), anyList() );
    }


    @Test
    public void isAuthorized_params_with_contextOverride()
        throws Exception {

        System.out.println( "  Test IsAuthorized (Context Override)" );

        when( mockSecurityManager.authenticatedSessionID() ).thenReturn( TEST_CIS_SESSION_ID );

        when( mockFuturePermissionSet.get() ).thenReturn( permissionSet );
        permissionSet.getAuthorizedPermissions().add( SessionRequired.name() );

        AuthorizationContext context = new AuthorizationContext( SessionRequired );
        context.put( AuthorizationContext.KEY_CAS_CONTEXT, "[CAS context override]" );

        testCasFilter.isAuthorized( mockFilterChain, context );
        verify( mockIdentityService )
            .isAuthorized( anyString(), eq( "[CAS context override]" ), anyList() );
    }


    @Test
    public void isAuthorized_notHandledByThisFilter()
        throws Exception {

        System.out.println( "  Test IsAuthorized (No Matching Roles)" );

        when( mockSecurityManager.authenticatedSessionID() ).thenReturn( TEST_CIS_SESSION_ID );

        permissionSet.getAuthorizedPermissions().clear();
        permissionSet.getAuthorizedPermissions().add( FSMessagingAdminApiViewThread.name() );

        AuthorizationContext context = new AuthorizationContext( SessionRequired );

        boolean actual = testCasFilter.isAuthorized( mockFilterChain, context );

        assertThat( actual, is( false ) );

        verify( mockFilterChain ).isAuthorized( context );
    }


    @Test
    public void isAuthorized_RuntimeException()
        throws Exception {

        System.out.println( "  Test IsAuthorized (isAuthorized Exception)" );

        when( mockSecurityManager.authenticatedSessionID() ).thenReturn( TEST_CIS_SESSION_ID );
        when( mockIdentityService.isAuthorized( anyString(), anyString(), anyList() ) )
            .thenThrow( new IllegalStateException( "What Happened?" ) );

        AuthorizationContext context = new AuthorizationContext( SessionRequired );

        boolean actual = testCasFilter.isAuthorized( mockFilterChain, context );

        assertThat( actual, is( false ) );
        verify( mockFilterChain ).isAuthorized( context );
    }

}

