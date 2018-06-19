package org.familysearch.cmp.authorization;

import org.familysearch.cmp.authorization.permissions.CmpMsgPermission;
import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.familysearch.engage.foundation.services.HttpRequestContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Profile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequest;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
//import static com.googlecode.catchexception.CatchException.catchException;
//import static com.googlecode.catchexception.CatchException.caughtException;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
//import static org.mockito.Mockito.*;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;



@Test(groups = "component")
@ContextConfiguration( classes = {AuthorizationAspectCT.TestConfiguration.class })
@ActiveProfiles( "component-test" )
public class AuthorizationAspectCT extends AbstractTestNGSpringContextTests {

    @Configuration
    @EnableAspectJAutoProxy
    @Profile("component-test")
    static class TestConfiguration {

        @Bean
        Controller service() {
            return new ResourceTestController();
        }

        @Bean
        AuthorizationAspect authorizationAspect() {
            return new AuthorizationAspect();
        }

        @Bean
        FoundationSecurityManager securityManager() {
            return mock( FoundationSecurityManager.class );
        }
    }

    @Autowired
    private Controller advisedController;

    @Autowired
    private FoundationSecurityManager securityManager;


//    @Mock
//    private FoundationSecurityManager mockSecMgr;


    @BeforeMethod
    public void setup() {
//        MockitoAnnotations.initMocks( this );

        reset( securityManager );
        HttpServletRequest request = mock( HttpServletRequest.class );
        HttpRequestContext.setNewContext( request, null );
    }


    @AfterMethod
    public void teardown() {
        HttpRequestContext.clearContext();
    }


    @Test
    public void testAdvise_Authorized_ReturnsData() {
        when( securityManager.authenticatedSessionID() ).thenReturn( "a-session-id" );
        when( securityManager.isAuthorized( Mockito.any( AuthorizationContext.class ) ) ).thenReturn( true );

        final String output = advisedController.protectedResourceMethod( "someInput" );

        assertThat( output, is( "someInput" ) );
        verify( securityManager, times(1) ).isAuthorized( any( AuthorizationContext.class ) );
    }


    @Test
    public void testAdvise_Establishes_AuthContext() {
        when( securityManager.authenticatedSessionID() ).thenReturn( "authenticated-session" );
        final ArgumentCaptor<AuthorizationContext> captor = ArgumentCaptor.forClass( AuthorizationContext.class );
        when( securityManager.isAuthorized( captor.capture() ) ).thenReturn( true );

        advisedController.protectedResourceMethod( null );

        //    assertThat(captor.getValue().getPermissionNames(), contains(FsMessagesPermission.SessionRequired.getName())); // TODO fix dependency problem
    }


    @Test
    public void testUnauthenticated_NullSessionId() {

        when( securityManager.authenticatedSessionID() ).thenReturn( null );

//        catchException( advisedController ).protectedResourceMethod( null );
//
//        assertThat( caughtException(), is( instanceOf( UnauthenticatedException.class ) ) );
    }


    @Test
    public void testUnauthenticated_ExpiredSessionId() {
        when( securityManager.authenticatedSessionID() ).thenReturn( "[CIS session]" );

//        catchException( advisedController ).protectedResourceMethod( null );
//
//        assertThat( caughtException(), is( instanceOf( UnauthorizedException.class ) ) );
    }


    @Test
    public void testAdvise_unauthorized() {
        when( securityManager.authenticatedSessionID() ).thenReturn( "a-session-id" );
        when( securityManager.isAuthorized( Mockito.any( AuthorizationContext.class ) ) ).thenReturn( false );

//        catchException( advisedController ).protectedResourceMethod( null );
//
//        assertThat( caughtException(), instanceOf( UnauthorizedException.class ) );
    }


    interface Controller {
        String protectedResourceMethod( String in );
    }


    static class ResourceTestController implements Controller {

        @Override
//        @PermissionRequired( FsMessagesPermission.SessionRequired)
        @PermissionRequired( CmpMsgPermission.SessionRequired )
        public String protectedResourceMethod( String in ) {
            return in;
        }
    }


}

