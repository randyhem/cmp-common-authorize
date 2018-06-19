
package org.familysearch.cmp.authorization;

/**
 * Exception to indicate the request requires authorization, but none exists.
 */
public class UnauthenticatedException extends RuntimeException {

    public UnauthenticatedException(String message) {
        super(message);
    }

}

