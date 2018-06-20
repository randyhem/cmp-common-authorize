package org.familysearch.cmp.authorization.permissions;

/**
 * Permissions used to protect access to Units resources.
 */
public enum CmpPermission implements org.familysearch.engage.foundation.security.Permission {

    /******************************************************************************
    *  1- From UserMessaging/FSMessagingDefaultContext
    ******************************************************************************/
    FSMessagingFullAccessUserRole,

    FSMessagingFullTimeAdminRole,



    /******************************************************************************
    *  2- From UserMessaging/FSMessagingSuportAdminContext
    ******************************************************************************/

    // The admin resource requires a permission to view a thread
    FSMessagingAdminApiViewThread,

    // The admin resource requires a permission to modify a thread
    FSMessagingAdminApiModifyThread,

    // The resource requires a permission to modify a thread
    FSMessagingModifyThread,

    // The resource requires an authenticated session.
    SessionRequired,


    /******************************************************************************
    *  3- From UserMessaging/UserMessagingContext
    ******************************************************************************/

    MessagingClientRole,

    UserMessagingAdminRole;


    /**
     * Returns the enumeration name of the permission.
     */
    @Override
    public String getName() {
    return name();
  }


}

