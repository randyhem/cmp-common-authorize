
/*
 * (c) 2018 by Intellectual Reserve, Inc. All rights reserved.
 */

package org.familysearch.cmp.authorization;

import org.familysearch.cmp.authorization.exception.UnauthenticatedException;
import org.familysearch.cmp.authorization.exception.UnauthorizedException;
import org.familysearch.cmp.authorization.permissions.CmpPermission;
import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

//import static org.mockito.Mockito.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;



@RunWith( SpringJUnit4ClassRunner.class )
@ContextConfiguration( classes = {AuthorizationAspectCT.TestConfiguration.class })
public class AuthorizationAspectCT {

    @Configuration
    @EnableAspectJAutoProxy
    static class TestConfiguration {

        @Bean
        TestResourceHttpController httpController() {
            System.out.println( "HTTP-Controller BEAN initialized ..." );
            return new TestResourceHttpController();
        }

        @Bean
        AuthorizationAspect authorizationAspect() {
            System.out.println( "AuthorizationAspect BEAN initialized ..." );
            return new AuthorizationAspect();
        }

        @Bean
        FoundationSecurityManager securityManager() {
            System.out.println( "FoundationSecurityManager BEAN initialized ..." );
            return mock( FoundationSecurityManager.class );
        }
    }


    private static final String AUTH_CAS_CONTEXT_KEY =  "authorizationContext.casContext";

    private static final String TEST_ARG =              "Some TEST input";
    private static final String TEST_CAS_CONTEXT =      "User-Messaging";
    private static final String TEST_VALID_SESSION =    "authenticated-session";

    private static int  testCnt = 0;
    private static Lock forceSerialLock = new ReentrantLock();


    @Autowired
    private TestResourceHttpController advisedController;

    @Autowired
    private FoundationSecurityManager securityManager;



    @Before
    public void setup() {

        // Force sequential test execution by requiring acquisition to exclusive lock!
        forceSerialLock.lock();
        ++testCnt;

        reset( securityManager );

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
    public void test_Authorized_Session_Success() {

        System.out.println( "  Valid Session Available Test (OK)");

        when( securityManager.authenticatedSessionID() ).thenReturn( TEST_VALID_SESSION );
        when( securityManager.isAuthorized( Mockito.any( AuthorizationContext.class ) ) ).thenReturn( true );

        String output = advisedController.protectedResourceMethod( TEST_ARG );

        assertThat( output, equalTo( TEST_ARG ) );
        verify( securityManager, times(1 ) ).isAuthorized( any( AuthorizationContext.class ) );
        verify( securityManager, times(0 ) ).casContext();
    }


    @Test
    public void test_Authorized_Session_Success_WithCAS() {

        System.out.println( "  Valid Session Available Plus CAS Test (OK)");

        ArgumentCaptor<AuthorizationContext> captor = ArgumentCaptor.forClass( AuthorizationContext.class );

        when( securityManager.authenticatedSessionID() ).thenReturn( TEST_VALID_SESSION );
        when( securityManager.isAuthorized( captor.capture() ) ).thenReturn( true );
        when( securityManager.casContext() ).thenReturn( TEST_CAS_CONTEXT );

        String output = advisedController.protectedCasResourceMethod( TEST_ARG );

        assertThat( output, equalTo( TEST_ARG ) );
        assertThat( captor.getValue(), notNullValue() );
        assertThat( captor.getValue().getPermissions(), notNullValue() );
        assertThat( captor.getValue().getPermissions().size(), equalTo( 1 ) );
        assertThat( captor.getValue().getPermissions().get(0), equalTo( CmpPermission.SessionRequired ) );
        assertThat( captor.getValue().get( AUTH_CAS_CONTEXT_KEY ), equalTo( TEST_CAS_CONTEXT ) );

        verify( securityManager, times(1) ).isAuthorized( any( AuthorizationContext.class ) );
        verify( securityManager, times(1) ).casContext();
    }


    @Test
    public void test_Authorized_Session_Correct_Permission() {

        System.out.println( "  Valid Session Available Test (Correct Permissions)");

        when( securityManager.authenticatedSessionID() ).thenReturn( TEST_VALID_SESSION );
        final ArgumentCaptor<AuthorizationContext> captor = ArgumentCaptor.forClass( AuthorizationContext.class );
        when( securityManager.isAuthorized( captor.capture() ) ).thenReturn( true );

        String output = advisedController.protectedResourceMethod( TEST_ARG );

        assertThat( output, equalTo( TEST_ARG ) );
        assertThat( captor.getValue(), notNullValue() );
        assertThat( captor.getValue().getPermissions(), notNullValue() );
        assertThat( captor.getValue().getPermissions().size(), equalTo( 1 ) );
        assertThat( captor.getValue().getPermissions().get(0), equalTo( CmpPermission.SessionRequired ) );

        verify( securityManager, times(1) ).isAuthorized( any( AuthorizationContext.class ) );
    }


    @Test( expected = UnauthenticatedException.class )
    public void testUnauthenticated_NullSessionId() {

        System.out.println( "  No Session Available Test (Unauthenticated Exception)" );

        when( securityManager.authenticatedSessionID() ).thenReturn( null );
        advisedController.protectedResourceMethod( TEST_ARG );
    }


    @Test( expected = UnauthorizedException.class )
    public void testAdvise_unauthorized() {

        System.out.println( "  Expired Session Test (Unauthorized Exception)" );

        when( securityManager.authenticatedSessionID() ).thenReturn( TEST_VALID_SESSION );
        when( securityManager.isAuthorized( Mockito.any( AuthorizationContext.class ) ) ).thenReturn( false );

        advisedController.protectedResourceMethod( TEST_ARG );
    }




    static class TestResourceHttpController {

        @PermissionRequired( value = {CmpPermission.SessionRequired} )
        public String protectedResourceMethod( String in ) {
            System.out.println( "  <<< ProtectedResourceMethod called >>>" );
            return in;
        }

        @PermissionRequired( value = {CmpPermission.SessionRequired},
            requireCheckSessionCasContext = true )
        public String protectedCasResourceMethod( String in ) {
            System.out.println( "  <<< ProtectedCasResourceMethod called >>>" );
            return in;
        }


    }

}

