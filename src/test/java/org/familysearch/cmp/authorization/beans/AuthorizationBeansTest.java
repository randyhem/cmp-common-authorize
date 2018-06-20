
/*
 * (c) 2018 by Intellectual Reserve, Inc. All rights reserved.
 */


package org.familysearch.cmp.authorization.beans;

import org.familysearch.cmp.authorization.ValidSessionOnlyAuthorizationFilter;
import org.familysearch.cmp.authorization.exception.UnauthenticatedException;
import org.familysearch.cmp.authorization.permissions.CmpPermission;
import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.AuthorizationFilterChain;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.ArrayList;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.*;


public class AuthorizationBeansTest {

    private static int  testCnt = 0;
    private static Lock forceSerialLock = new ReentrantLock();

    private static final String TEST_CAS_CONTEXT =          "UserMessaging";
    private static final String TEST_APP_CAS_CONTEXT =      "FSMessagingAdminContext";
    private static final String TEST_SESSION_ROLE_NAME =    CmpPermission.SessionRequired.name();
    private static final CmpPermission TEST_PERMISSION =    CmpPermission.SessionRequired;
    private static final CmpPermission OTHER_PERMISSION =   CmpPermission.UserMessagingAdminRole;


//    @Mock
//    private FoundationSecurityManager mockSecurityManager;

    private AuthorizationBeans          testAuthBeans;

    private FoundationSecurityManager   testSecurityMgr;

    private String                      testSessionRoleName;
    private List<CmpPermission>         testRolesLst;


    @Before
    public void setUp()
        throws Exception {

        // Force sequential test execution by requiring acquisition to exclusive lock!
        forceSerialLock.lock();
        ++testCnt;

        MockitoAnnotations.initMocks( this );
        testAuthBeans = new AuthorizationBeans();

        testSessionRoleName = TEST_SESSION_ROLE_NAME;
        testRolesLst = new ArrayList<>();
        testRolesLst.add( CmpPermission.FSMessagingModifyThread );
        testRolesLst.add( CmpPermission.FSMessagingAdminApiViewThread );

        System.out.println( String.format( "\nTest %d Setup", testCnt ) );
        System.out.flush();
    }


    @After
    public void teardown() {
        System.out.println( String.format("Test %d Teardown", testCnt) );
        System.out.flush();
        forceSerialLock.unlock();
    }


    @Test( expected = IllegalArgumentException.class )
    public void testGetSecurityMgr_BadArgs()
        throws Exception {

        System.out.println( "  Test Get SecurityMgr (Bad Args)" );
        List<CmpPermission> permList = null;

        testAuthBeans.securityManager( TEST_CAS_CONTEXT,
                                       testSessionRoleName,
                                       permList,
                                       TEST_APP_CAS_CONTEXT );
    }


    @Test
    public void testGetSecurityMgr_Ok()
        throws Exception {

        System.out.println( "  Test Get SecurityMgr (Success)" );

        testAuthBeans.securityManager( TEST_CAS_CONTEXT,
                                       testSessionRoleName,
                                       testRolesLst,
                                       TEST_APP_CAS_CONTEXT );
    }

/*
    @Test( expected = UnauthenticatedException.class )
    public void testIsAuthorized_NoUserIdOnRequest()
        throws Exception {

        System.out.println( "  Test isAuthorized (No Session Token)" );

        AuthorizationContext context = new AuthorizationContext( TEST_PERMISSION );
        when( mockSecurityManager.authenticatedUserID() ).thenReturn( null );

        testSessionFilter.isAuthorized( null, context );
        verify( mockSecurityManager, times(1) ).authenticatedUserID();
    }


    @Test( expected = UnauthenticatedException.class )
    public void testIsAuthorized_NullUserIdOnRequest()
        throws Exception {

        System.out.println( "  Test isAuthorized (Null Session Token)" );

        AuthorizationContext context = new AuthorizationContext( TEST_PERMISSION );
        when( mockSecurityManager.authenticatedUserID() ).thenReturn( "null" );

        testSessionFilter.isAuthorized( null, context );
        verify( mockSecurityManager, times(1) ).authenticatedUserID();
    }


    @Test
    public void testIsAuthorized_ReturnsFilterChainResult_WhenPermissionIsUnhandled()
        throws Exception {

        System.out.println( "  Test isAuthorized (Filter Chain Reject)" );

        AuthorizationContext context = new AuthorizationContext( OTHER_PERMISSION );
        AuthorizationFilterChain mockFilterChain = mock( AuthorizationFilterChain.class );

        assertThat( testSessionFilter.isAuthorized( mockFilterChain, context ), equalTo( false ) );
        verify( mockSecurityManager, times(1) ).authenticatedUserID();
        verify( mockFilterChain, times(1) ).isAuthorized( context );
    }


    @Test
    public void testIsAuthorized_CallsFilterChain_WhenPermissionIsUnhandled()
        throws Exception {

        System.out.println( "  Test isAuthorized (Filter Chain Reject)" );

        AuthorizationContext context = new AuthorizationContext( OTHER_PERMISSION );
        AuthorizationFilterChain mockFilterChain = mock( AuthorizationFilterChain.class );
        when( mockFilterChain.isAuthorized( any( AuthorizationContext.class ) ) ).thenReturn( true );

        assertThat( testSessionFilter.isAuthorized( mockFilterChain, context ), equalTo( true ) );
        verify( mockFilterChain, times(1) ).isAuthorized( context );
    }
*/

}

