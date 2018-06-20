
package org.familysearch.cmp.authorization.exception;

/**
 * Exception thrown to indicate the request requires authorization,
 * but the user does not have sufficient privileges.
 */
public class UnauthorizedException extends RuntimeException {

    public static final String DEFAULT_MESSAGE = "User is not authorized to access the resource.";


    public UnauthorizedException() {
        this(DEFAULT_MESSAGE);
    }


    public UnauthorizedException(String message) {
        super( message );
    }


}

