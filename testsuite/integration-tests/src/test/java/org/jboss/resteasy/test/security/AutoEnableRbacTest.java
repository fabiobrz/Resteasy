package org.jboss.resteasy.test.security;

import java.util.Hashtable;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClientEngine;
import org.jboss.resteasy.setup.AbstractUsersRolesSecurityDomainSetup;
import org.jboss.resteasy.spi.HttpResponseCodes;
import org.jboss.resteasy.test.security.resource.AutoEnableRbacResource;
import org.jboss.resteasy.utils.PortProviderUtil;
import org.jboss.resteasy.utils.TestUtil;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Integration tests for RESTEASY-3789: {@code RoleBasedSecurityFeature} must be registered by
 * default (i.e. when {@code resteasy.role.based.security} is absent), and must be suppressible
 * by explicitly setting the property to {@code false}.
 *
 * <h2>Test matrix (D-13)</h2>
 * <ul>
 * <li>NT-1 {@link #rbac_autoEnabled_withRolesAllowed_wrongRole_returns403()}</li>
 * <li>NT-2 {@link #rbac_autoEnabled_withRolesAllowed_correctRole_returns200()}</li>
 * <li>NT-3 {@link #rbac_autoEnabled_withDenyAll_returns403()}</li>
 * <li>NT-4 {@link #rbac_autoEnabled_withPermitAll_returns200()}</li>
 * <li>NT-5 {@link #rbac_explicitFalse_annotationsIgnored_returns200()}</li>
 * <li>NT-6 {@link #rbac_explicitTrue_stillWorks_returns403()}</li>
 * </ul>
 *
 * <h2>Deployments</h2>
 * <ul>
 * <li>{@value #DEPLOY_DEFAULT} — no {@code resteasy.role.based.security} (RBAC on by default)</li>
 * <li>{@value #DEPLOY_FALSE} — {@code resteasy.role.based.security=false} (opt-out)</li>
 * <li>{@value #DEPLOY_TRUE} — {@code resteasy.role.based.security=true} (explicit opt-in, regression guard)</li>
 * </ul>
 *
 * <h2>Users / roles</h2>
 * <ul>
 * <li>{@code userA / password1} — assigned role {@code ROLE_A} only</li>
 * <li>{@code userB / password1} — assigned role {@code ROLE_B} only</li>
 * </ul>
 *
 * @tpSubChapter Security
 * @tpChapter Integration tests
 * @tpTestCaseDetails RESTEASY-3789: RoleBasedSecurityFeature enabled by default
 * @tpSince RESTEasy 7.0
 */
@ServerSetup(AutoEnableRbacTest.SecurityDomainSetup.class)
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@Tag("NotForBootableJar")
public class AutoEnableRbacTest {

    /** Deployment with no {@code resteasy.role.based.security} context-param (RBAC auto-enabled). */
    static final String DEPLOY_DEFAULT = "AutoEnableRbacTestDefault";

    /** Deployment with {@code resteasy.role.based.security=false} (RBAC explicitly disabled). */
    static final String DEPLOY_FALSE = "AutoEnableRbacTestFalse";

    /** Deployment with {@code resteasy.role.based.security=true} (RBAC explicitly enabled — regression guard). */
    static final String DEPLOY_TRUE = "AutoEnableRbacTestTrue";

    // ─────────────────────────────────────────────────────────────────────────
    // Clients
    // ─────────────────────────────────────────────────────────────────────────

    /** Authenticated as {@code userA} (role: {@code ROLE_A}) — wrong role for {@code @RolesAllowed("ROLE_B")}. */
    private static ResteasyClient clientRoleA;

    /** Authenticated as {@code userB} (role: {@code ROLE_B}) — correct role. */
    private static ResteasyClient clientRoleB;

    @BeforeAll
    public static void initClients() {
        clientRoleA = buildBasicAuthClient("userA", "password1");
        clientRoleB = buildBasicAuthClient("userB", "password1");
    }

    @AfterAll
    public static void closeClients() {
        clientRoleA.close();
        clientRoleB.close();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployments
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Deployment with NO {@code resteasy.role.based.security} context-param.
     * After the RESTEASY-3789 fix, {@code RoleBasedSecurityFeature} is registered by default.
     */
    @Deployment(name = DEPLOY_DEFAULT)
    public static Archive<?> deployDefault() {
        WebArchive war = TestUtil.prepareArchive(DEPLOY_DEFAULT);
        war.addAsWebInfResource(AutoEnableRbacTest.class.getPackage(),
                "rbac-auto-enable-jboss-web.xml", "jboss-web.xml")
                .addAsWebInfResource(AutoEnableRbacTest.class.getPackage(),
                        "rbac-auto-enable-web-default.xml", "web.xml");
        return TestUtil.finishContainerPrepare(war, new Hashtable<>(), AutoEnableRbacResource.class);
    }

    /**
     * Deployment with {@code resteasy.role.based.security=false}.
     * {@code RoleBasedSecurityFeature} is explicitly disabled; RBAC annotations are ignored.
     */
    @Deployment(name = DEPLOY_FALSE)
    public static Archive<?> deployFalse() {
        WebArchive war = TestUtil.prepareArchive(DEPLOY_FALSE);
        war.addAsWebInfResource(AutoEnableRbacTest.class.getPackage(),
                "rbac-auto-enable-jboss-web.xml", "jboss-web.xml")
                .addAsWebInfResource(AutoEnableRbacTest.class.getPackage(),
                        "rbac-auto-enable-web-false.xml", "web.xml");
        return TestUtil.finishContainerPrepare(war, new Hashtable<>(), AutoEnableRbacResource.class);
    }

    /**
     * Deployment with {@code resteasy.role.based.security=true}.
     * Explicit opt-in; verifies the fix did not regress the existing behaviour.
     */
    @Deployment(name = DEPLOY_TRUE)
    public static Archive<?> deployTrue() {
        WebArchive war = TestUtil.prepareArchive(DEPLOY_TRUE);
        war.addAsWebInfResource(AutoEnableRbacTest.class.getPackage(),
                "rbac-auto-enable-jboss-web.xml", "jboss-web.xml")
                .addAsWebInfResource(AutoEnableRbacTest.class.getPackage(),
                        "rbac-auto-enable-web-true.xml", "web.xml");
        return TestUtil.finishContainerPrepare(war, new Hashtable<>(), AutoEnableRbacResource.class);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NT-1 / NT-2: RBAC auto-enabled, @RolesAllowed("ROLE_B")
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * NT-1: {@code resteasy.role.based.security} not set; user carries only {@code ROLE_A}.
     * {@code @RolesAllowed("ROLE_B")} must deny the request with 403.
     *
     * @tpTestDetails NT-1 (RESTEASY-3789)
     */
    @Test
    @OperateOnDeployment(DEPLOY_DEFAULT)
    public void rbac_autoEnabled_withRolesAllowed_wrongRole_returns403() {
        Response response = clientRoleA.target(url(DEPLOY_DEFAULT, "/rbac-auto/roles-allowed")).request().get();
        try {
            Assertions.assertEquals(HttpResponseCodes.SC_FORBIDDEN, response.getStatus(),
                    "NT-1: @RolesAllowed(ROLE_B) must deny userA (ROLE_A) with 403 when no property is set");
        } finally {
            response.close();
        }
    }

    /**
     * NT-2: {@code resteasy.role.based.security} not set; user carries {@code ROLE_B}.
     * {@code @RolesAllowed("ROLE_B")} must allow the request with 200.
     *
     * @tpTestDetails NT-2 (RESTEASY-3789)
     */
    @Test
    @OperateOnDeployment(DEPLOY_DEFAULT)
    public void rbac_autoEnabled_withRolesAllowed_correctRole_returns200() {
        Response response = clientRoleB.target(url(DEPLOY_DEFAULT, "/rbac-auto/roles-allowed")).request().get();
        try {
            Assertions.assertEquals(HttpResponseCodes.SC_OK, response.getStatus(),
                    "NT-2: @RolesAllowed(ROLE_B) must allow userB (ROLE_B) with 200 when no property is set");
        } finally {
            response.close();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NT-3: RBAC auto-enabled, @DenyAll
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * NT-3: {@code resteasy.role.based.security} not set; endpoint has {@code @DenyAll}.
     * Must return 403 even for an authenticated user.
     *
     * @tpTestDetails NT-3 (RESTEASY-3789)
     */
    @Test
    @OperateOnDeployment(DEPLOY_DEFAULT)
    public void rbac_autoEnabled_withDenyAll_returns403() {
        Response response = clientRoleA.target(url(DEPLOY_DEFAULT, "/rbac-auto/deny-all")).request().get();
        try {
            Assertions.assertEquals(HttpResponseCodes.SC_FORBIDDEN, response.getStatus(),
                    "NT-3: @DenyAll must return 403 when no property is set");
        } finally {
            response.close();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NT-4: RBAC auto-enabled, @PermitAll
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * NT-4: {@code resteasy.role.based.security} not set; endpoint has {@code @PermitAll}.
     * Must return 200 regardless of the caller's role.
     *
     * @tpTestDetails NT-4 (RESTEASY-3789)
     */
    @Test
    @OperateOnDeployment(DEPLOY_DEFAULT)
    public void rbac_autoEnabled_withPermitAll_returns200() {
        Response response = clientRoleA.target(url(DEPLOY_DEFAULT, "/rbac-auto/permit-all")).request().get();
        try {
            Assertions.assertEquals(HttpResponseCodes.SC_OK, response.getStatus(),
                    "NT-4: @PermitAll must return 200 when no property is set");
        } finally {
            response.close();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NT-5: resteasy.role.based.security=false — RBAC opt-out
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * NT-5: {@code resteasy.role.based.security=false}; user carries only {@code ROLE_A}.
     * Because RBAC is explicitly disabled, {@code @RolesAllowed("ROLE_B")} is ignored
     * and the request must succeed with 200.
     *
     * @tpTestDetails NT-5 (RESTEASY-3789)
     */
    @Test
    @OperateOnDeployment(DEPLOY_FALSE)
    public void rbac_explicitFalse_annotationsIgnored_returns200() {
        Response response = clientRoleA.target(url(DEPLOY_FALSE, "/rbac-auto/roles-allowed")).request().get();
        try {
            Assertions.assertEquals(HttpResponseCodes.SC_OK, response.getStatus(),
                    "NT-5: @RolesAllowed(ROLE_B) must be ignored (200) when resteasy.role.based.security=false");
        } finally {
            response.close();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NT-6: resteasy.role.based.security=true — regression guard
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * NT-6: {@code resteasy.role.based.security=true}; user carries only {@code ROLE_A}.
     * {@code @RolesAllowed("ROLE_B")} must still deny the request with 403.
     * Verifies the fix did not break the explicit opt-in behaviour.
     *
     * @tpTestDetails NT-6 (RESTEASY-3789)
     */
    @Test
    @OperateOnDeployment(DEPLOY_TRUE)
    public void rbac_explicitTrue_stillWorks_returns403() {
        Response response = clientRoleA.target(url(DEPLOY_TRUE, "/rbac-auto/roles-allowed")).request().get();
        try {
            Assertions.assertEquals(HttpResponseCodes.SC_FORBIDDEN, response.getStatus(),
                    "NT-6: @RolesAllowed(ROLE_B) must deny userA (ROLE_A) with 403 when resteasy.role.based.security=true");
        } finally {
            response.close();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static ResteasyClient buildBasicAuthClient(String username, String password) {
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username, password);
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, credentials);
        CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultCredentialsProvider(credentialsProvider)
                .build();
        ApacheHttpClientEngine engine = ApacheHttpClientEngine.create(httpClient);
        return ((ResteasyClientBuilder) ClientBuilder.newBuilder()).httpEngine(engine).build();
    }

    private static String url(String deploymentName, String path) {
        return PortProviderUtil.generateURL(path, deploymentName);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Security domain setup
    // ─────────────────────────────────────────────────────────────────────────

    static class SecurityDomainSetup extends AbstractUsersRolesSecurityDomainSetup {

        SecurityDomainSetup() {
            super(AutoEnableRbacTest.class.getResource("rbac-auto-enable-users.properties"),
                    AutoEnableRbacTest.class.getResource("rbac-auto-enable-roles.properties"));
        }

        @Override
        public java.util.Map<String, String> getSecurityDomainConfig() {
            return java.util.Collections.singletonMap("rbacAutoEnableDomain", "rbacAutoEnableRealm");
        }
    }
}
