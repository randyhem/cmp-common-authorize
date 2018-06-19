package org.familysearch.cmp.authorization;

import org.familysearch.engage.foundation.security.AuthorizationContext;
import org.familysearch.engage.foundation.security.AuthorizationFilterChain;
import org.familysearch.engage.foundation.security.FoundationSecurityManager;
import org.familysearch.engage.foundation.security.Permission;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.*;

public class ValidSessionOnlyAuthorizationFilterTest {

  public static enum TestPermissions implements Permission {
    SESSION_REQUIRED,
    OTHER_PERMISSION;

    @Override
    public String getName() {
      return this.name();
    }
  }

  @InjectMocks
  private ValidSessionOnlyAuthorizationFilter fixture;

  @Mock
  private FoundationSecurityManager mockSecurityManager;

  @BeforeMethod
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);

    when(mockSecurityManager.authenticatedUserID()).thenReturn("not-null-string");

    fixture.setSessionRequiredPermissionName( TestPermissions.SESSION_REQUIRED.name());
  }

  @Test
  public void testIsAuthorized() throws Exception {
    final AuthorizationContext context = new AuthorizationContext( TestPermissions.SESSION_REQUIRED);
    when(mockSecurityManager.authenticatedUserID()).thenReturn("not-null-string");

    final boolean authorized = fixture.isAuthorized(null, context);
    assertThat(authorized, is(true));
  }

  @Test(expectedExceptions = UnauthenticatedException.class)
  public void testIsAuthorized_NoUserIdOnRequest() throws Exception {
    final AuthorizationContext context = new AuthorizationContext( TestPermissions.SESSION_REQUIRED);
    when(mockSecurityManager.authenticatedUserID()).thenReturn(null);

    final boolean authorized = fixture.isAuthorized(null, context);
  }

  @Test(expectedExceptions = UnauthenticatedException.class)
  public void testIsAuthorized_NullUserIdOnRequest() throws Exception {
    final AuthorizationContext context = new AuthorizationContext( TestPermissions.SESSION_REQUIRED);
    when(mockSecurityManager.authenticatedUserID()).thenReturn("null");

    final boolean authorized = fixture.isAuthorized(null, context);
  }

  @Test
  public void testIsAuthorized_ReturnsFilterChainResult_WhenPermissionIsUnhandled() throws Exception {
    final AuthorizationContext context = new AuthorizationContext( TestPermissions.OTHER_PERMISSION);
    final AuthorizationFilterChain mockFilterChain = mock(AuthorizationFilterChain.class);

    final boolean authorized = fixture.isAuthorized(mockFilterChain, context);
    assertThat(authorized, is(false));
  }

  @Test
  public void testIsAuthorized_CallsFilterChain_WhenPermissionIsUnhandled() throws Exception {
    final AuthorizationContext context = new AuthorizationContext( TestPermissions.OTHER_PERMISSION);
    final AuthorizationFilterChain mockFilterChain = mock(AuthorizationFilterChain.class);

    fixture.isAuthorized(mockFilterChain, context);
    verify(mockFilterChain).isAuthorized(context);
  }

  @Test(expectedExceptions = UnauthenticatedException.class)
  public void testIsAuthorized_ThrowsUnauthenticatedException_WhenTheRequestIsUnauthenticated_EvenWhenPermissionIsUnhandled() throws Exception {
    final AuthorizationContext context = new AuthorizationContext( TestPermissions.OTHER_PERMISSION);
    final AuthorizationFilterChain mockFilterChain = mock(AuthorizationFilterChain.class);

    when(mockSecurityManager.authenticatedUserID()).thenReturn(null);

    fixture.isAuthorized(mockFilterChain, context);
  }


}
