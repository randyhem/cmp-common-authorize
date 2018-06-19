
package org.familysearch.cmp.authorization;

import org.familysearch.cmp.authorization.permissions.CmpMsgPermission;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


/**
 * Annotation for a method to indicate that proper authorization is
 * required for a user to access it.  The value of the annotation
 * is one or more Permission values.  Please note that if multiple
 * permissions are specified, they will be treated as OR conditions,
 * i.e., the affected method can be called if the user has any one
 * of the listed permissions.
 *
 * (Shamelessly stolen from the units project)
 */
@Inherited
@Documented
@Target( ElementType.METHOD )
@Retention( RetentionPolicy.RUNTIME )
public @interface PermissionRequired {

    CmpMsgPermission[] value();

    boolean requireCheckSessionCasContext() default false;

}

