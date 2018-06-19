
package org.familysearch.cmp.authorization.util;


/**
 * (Shamelessly stolen from the units project)
 */
public class StringUtils {

    private static final String NULL_STRING = "null";


    public static boolean isNullorEmpty( String  theString ) {

        return( (theString == null) || theString.isEmpty() || NULL_STRING.equals( theString ) );
    }


}

