
package org.familysearch.cmp.authorization;

import jersey.repackaged.com.google.common.base.Preconditions;
//import org.familysearch.cmp.messages.dal.entity.Participant;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * Created by randyhem on 3/31/2016.
 *
 *  Simple bean that provides a method to validate session User-ID against
 *  an arbitrary User-ID.
 */
@Component
public class UserIdEnforcer {

    private static final Logger ID_LOGGER = LoggerFactory.getLogger( UserIdEnforcer.class );

    private final FoundationSecurityManager  foundSecurityMgr;


    @Autowired
    public UserIdEnforcer( FoundationSecurityManager foundationSecurityMgr ) {

        Preconditions.checkArgument( foundationSecurityMgr != null, "No FoundationSecurityManager bean provided" );

        this.foundSecurityMgr = foundationSecurityMgr;
    }


    /**
     *  Using the internal Foundation Security Manager, return the
     *   current authorization session token.
     *
     * @return String  - current session authorization token.
     */
    public String getSessionToken() {
        return( foundSecurityMgr.authenticatedSessionID() );
    }


    /**
     *
     *  Using the internal Foundation Security Manager, return the
     *   CIS user ID associated with the active authenticated session.
     *
     * @return String  - CIS User-ID of the authenticated user.
     */
    public String getSessionUserId() {
        return( foundSecurityMgr.authenticatedUserID() );
    }


    /**
     *  Ensure that the provided User-ID matches the FS session User-ID.  If not
     *      throw UnauthorizedException.  Use external logger for warning message.
     *
     * @param userId            - User ID to be validated
     * @param activityUnderway  - Web-Service activity being attempted
     * @param srcLogger         - Logger to be used to generate warning message
     */
    public boolean enforceUserIdIsAuthenticated(String  userId,
                                                String  activityUnderway,
                                                Logger  srcLogger ) {

        String authenticatedUserID = foundSecurityMgr.authenticatedUserID();


        if ( ! userIdsMatch(authenticatedUserID, userId) ) {
            if ( srcLogger != null ) {

                srcLogger.warn( "Rejecting {} request in behalf of user: {}, session user is: {}",
                                 (( activityUnderway != null )
                                        ? ( '\'' + activityUnderway + "' " )
                                        : "" ),
                                 userId,
                                 authenticatedUserID );
            }
            throw new UnauthorizedException();
        }
        return( true );
    }

    // allow a few rules for what constitutes a match
    protected boolean userIdsMatch(String authenticatedUser, String userToValidate) {

        if (authenticatedUser == null) {
            return false;
        }

        // under normal circumstances the authenticated user must be the same as the author,
        // however in the case where our UserMessagingServiceAccount is the author, we change
        // the author to a well known contributor account.

        // make sure that we don't block it in that case

        if (authenticatedUser.startsWith("cis.proc") && userToValidate.startsWith("cis.wkca")) {
            return true;
        }

        // otherwise they must match

        return authenticatedUser.equals(userToValidate);
    }


    /**
     *  Ensure that the provided User-ID matches the FS session User-ID.  If not
     *      throw UnauthorizedException.  Use internal logger for warning message.
     *
     * @param userId            - User ID to be validated
     * @param activityUnderway  - Web-Service activity being attempted
     */
    public boolean enforceUserIdIsAuthenticated(String  userId,
                                                String  activityUnderway ) {

        return( enforceUserIdIsAuthenticated( userId, activityUnderway, ID_LOGGER ) );
    }


    /**
     *  Ensure that the provided User-ID matches the FS session User-ID.  If not
     *      throw UnauthorizedException.  Unspecifed activity in progress.
     *      Use internal logger for warning message.
     *
     * @param userId            - User ID to be validated
     */
    public boolean enforceUserIdIsAuthenticated(String  userId ) {

        return( enforceUserIdIsAuthenticated( userId, null, ID_LOGGER ) );
    }


  /**
   * Asserts that the userId provided is found in the list of {@link Participant} objects provided.
   *
   * @param participantList a list of participants that will be used to enforce that one of them is the authenticated user
   * @param activityUnderway description of the activity that will be completed if the authorization check succeeds
   * @param srcLogger Logger to be used to generate warning message
   * @throws UnauthorizedException
   */
/*
    public void enforceCurrentUserIsParticipant(
        Set<Participant> participantList,
        String activityUnderway,
        Logger srcLogger ) {

        Preconditions.checkArgument(participantList != null, "participant list must not be null");

        String authenticatedUserID = foundSecurityMgr.authenticatedUserID();

        List<String> participantIds = participantList.stream()
            .map(p -> p.getCisUserId())
            .collect(Collectors.toList());

        if ( (authenticatedUserID == null) || ! participantIds.contains(authenticatedUserID)) {
            if ( srcLogger != null ) {

                srcLogger.warn( "Rejecting {} request because session user {} is not a participant",
                    (( activityUnderway != null )
                        ? ( '\'' + activityUnderway + "' " )
                        : "" ),
                    authenticatedUserID );
            }
            throw new UnauthorizedException(
                "Logged in user is not a participant and does not have access to perform activity: " + activityUnderway);
        }
    }
*/

}
