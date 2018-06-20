package org.familysearch.cmp.authorization;

//import org.familysearch.cmp.messages.dal.entity.Participant;
import org.familysearch.cmp.authorization.exception.UnauthorizedException;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;


public class UserIdEnforcerTest {

    private static Logger LOGGER = LoggerFactory.getLogger( UserIdEnforcerTest.class );

    private static final String testUserId = "cis.user.TEST-TEST";
    private static final String testSessionId = "test session id";
    private static final String testActivity = "get-thread-messages";

    private static final String serviceAccountId = "cis.proc.MMMM-JJJ";
    private static final String wkcAccountId = "cis.wkca.MERE-ERE";

//    private Set<Participant> testParticipants;

    // Test object
    private UserIdEnforcer testObject;

    // Mocked dependencies
    @Mock
    private FoundationSecurityManager mockSecurityManager;

    @Before
    public void setUp()
        throws IOException {
        MockitoAnnotations.initMocks( this );

//        testParticipants = new HashSet<>();
//        testParticipants.add( createParticipantWithId( "participant A" ) );
//        testParticipants.add( createParticipantWithId( "participant B" ) );
//        testParticipants.add( createParticipantWithId( "participant C" ) );
//        testParticipants.add( createParticipantWithId( "participant D" ) );
//        testParticipants.add( createParticipantWithId( testUserId ) );

        when( mockSecurityManager.authenticatedUserID() ).thenReturn( testUserId );
        when( mockSecurityManager.authenticatedSessionID() ).thenReturn( testSessionId );

        testObject = new UserIdEnforcer( mockSecurityManager );
    }

  /*
  enforceCurrentUserIsParticipant
   */


/*
    @Test
    public void enforceCurrentUserIsParticipant_shouldSucceed_whenTheAuthenticatedUserIsInTheParticipantSet() {
        testObject.enforceCurrentUserIsParticipant( testParticipants, testActivity, LOGGER );
    }


    @Test
    public void enforceCurrentUserIsParticipant_shouldThrowUnauthorizedException_whenTheAuthenticatedUserIsNotInTheParticipantSet() {
        testParticipants.remove( createParticipantWithId( testUserId ) );

        String failMsg = assertUnauthorizedException(
            () -> testObject.enforceCurrentUserIsParticipant( testParticipants, testActivity, LOGGER )
        );

        assertThat( failMsg, containsString( "Logged in user is not a participant and does not have access to perform activity" ) );
        assertThat( failMsg, containsString( testActivity ) );
    }

    @Test
    public void enforceCurrentUserIsParticipant_shouldThrowUnauthorizedException_whenTheAuthenticatedUserIsNull() {
        when( mockSecurityManager.authenticatedUserID() ).thenReturn( null );

        String failMsg = assertUnauthorizedException(
            () -> testObject.enforceCurrentUserIsParticipant( testParticipants, testActivity, LOGGER )
        );

        assertThat( failMsg, containsString( "Logged in user is not a participant and does not have access to perform activity" ) );
        assertThat( failMsg, containsString( testActivity ) );
    }

    @Test(expected = IllegalArgumentException.class)
    public void enforceCurrentUserIsParticipant_shouldThrowAnIllegalArgumentException_whenTheParticipantSetIsNull() {
        testObject.enforceCurrentUserIsParticipant( null, testActivity, LOGGER );
    }
*/


  /*
  enforceUserIdIsAuthenticated
   */

    @Test
    public void isUserIdValid_shouldSucceed_whenTheUserIdIsTheLoggedInUser() {
        testObject.enforceUserIdIsAuthenticated( testUserId, testActivity, LOGGER );
    }


    @Test
    public void isUserIdValid_shouldThrowUnauthorizedException_whenTheUserIdIsNotTheLoggedInUser() {
        when( mockSecurityManager.authenticatedUserID() ).thenReturn( "cis.user.SOMEONE-ELSE" );

        String failMsg = assertUnauthorizedException(
            () -> testObject.enforceUserIdIsAuthenticated( testUserId, testActivity, LOGGER )
        );

        assertThat( failMsg, containsString( "User is not authorized to access the resource." ) );
    }


    @Test
    public void isUserIdValid_shouldThrowUnauthorizedException_whenTheAuthenticatedUserIsNull() {
        when( mockSecurityManager.authenticatedUserID() ).thenReturn( null );

        String failMsg = assertUnauthorizedException(
            () -> testObject.enforceUserIdIsAuthenticated( testUserId, testActivity, LOGGER )
        );

        assertThat( failMsg, containsString( "User is not authorized to access the resource." ) );
    }


    @Test
    public void isUserIdValid_shouldAcceptANullActivity() {
        testObject.enforceUserIdIsAuthenticated( testUserId, null, LOGGER );
    }


    @Test
    public void isUserIdValid_shouldAcceptANullLogger() {
        testObject.enforceUserIdIsAuthenticated( testUserId, testActivity, null );
    }


    @Test
    public void isUserIdValid_shouldAcceptANullActivityAndLogger() {
        testObject.enforceUserIdIsAuthenticated( testUserId, null, null );
    }


    @Test
    public void isUserIdValid_testMethodOverload_withNoLogger() {
        testObject.enforceUserIdIsAuthenticated( testUserId, testActivity );
    }


    @Test
    public void isUserIdValid_testMethodOverload() {

        testObject.enforceUserIdIsAuthenticated( testUserId );
    }



  /*
  getSessionToken and getSessionUserId
   */

    @Test
    public void getSessionToken_shouldReturnTheSessionId() {
        String result = testObject.getSessionToken();
        assertThat( result, is( testSessionId ) );
    }


    @Test
    public void getSessionUserId_shouldReturnTheAuthenticatedUserId() {
        String result = testObject.getSessionUserId();
        assertThat( result, is( testUserId ) );
    }


    /*
     user id matching routine
     */
    @Test
    public void test_wkcaShouldBeAllowedAsAuthor()
        throws Exception {

        // if the service account is authenticated it can match the wkc account
        assertThat( testObject.userIdsMatch( serviceAccountId, wkcAccountId ), equalTo( true ) );
    }


    @Test
    public void test_wkcaShouldNotBeAllowedAsAuuthenticatedId()
        throws Exception {

        // if the wkc account is authenticated, it should not match the service account
        assertThat( testObject.userIdsMatch( wkcAccountId, serviceAccountId ), equalTo( false ) );
    }


    @Test
    public void test_nullAccountFails()
        throws Exception {

        // null should not match
        assertThat( testObject.userIdsMatch( null, testUserId ), equalTo( false ) );
    }


    @Test
    public void test_accountsShouldNotMatch()
        throws Exception {

        // a regular account should not match the service account
        assertThat( testObject.userIdsMatch( testUserId, serviceAccountId ), equalTo( false ) );
    }


    @Test
    public void test_serviceShouldNotMatchRegularAccount()
        throws Exception {

        // service account won't match for a regular account
        assertThat( testObject.userIdsMatch( serviceAccountId, testUserId ), equalTo( false ) );
    }


    @Test
    public void test_regularAccountsShouldMatch()
        throws Exception {

        // and two equal accounts should work
        assertThat( testObject.userIdsMatch( testUserId, testUserId ), equalTo( true ) );
    }



  /*
  Helper methods
   */
/*
    private Participant createParticipantWithId( String id ) {
        Participant p = new Participant( id, 0, null );
        return p;
    }
*/


    private String assertUnauthorizedException( Runnable function ) {
        try {
            function.run();
            throw new AssertionError( "Test expected an UnauthorizedException to be thrown before this statement" );
        }
        catch( UnauthorizedException e ) {
            return e.getMessage();
        }
    }


}

