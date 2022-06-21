/*
 * Copyright DataStax, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.datastax.oss.pulsar.auth;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.security.Keys;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataCommand;
import org.apache.pulsar.broker.authentication.AuthenticationState;
import org.apache.pulsar.common.api.AuthData;
import org.junit.jupiter.api.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.AccessTokenResponse;
import org.tmt.embedded_keycloak.EmbeddedKeycloak;
import org.tmt.embedded_keycloak.KeycloakData;
import org.tmt.embedded_keycloak.Settings;
import org.tmt.embedded_keycloak.impl.StopHandle;
import scala.collection.immutable.Set;
import scala.concurrent.Await;
import scala.concurrent.ExecutionContext;
import scala.concurrent.Future;
import scala.concurrent.duration.Duration;
import scala.jdk.javaapi.CollectionConverters;

import javax.naming.AuthenticationException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * Class to test the integration between the OpenID authentication classes and an embedded Keycloak process.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class OpenIDKeycloakIntegrationTest {

    String KEYCLOAK_VERSION = "16.1.0";

    int KEYCLOAK_PORT = 8080;
    String KEYCLOAK_URL = "http://localhost:" + KEYCLOAK_PORT + "/auth";
    String KEYCLOAK_MASTER_REALM_URL = KEYCLOAK_URL + "/realms/master";

    StopHandle stopHandle = null;

    @BeforeAll
    public void setUpKeycloak() throws Exception {
        // In order to simplify the test, we just use the master realm. Users will have more complicated
        // configurations. This test is not verifying those components, as they should be independent.
        KeycloakData.AdminUser adminUser = new KeycloakData.AdminUser("admin", "admin");
        Set<KeycloakData.Realm> realmSet = CollectionConverters.asScala(Collections.emptySet()).toSet();
        KeycloakData data = new KeycloakData(adminUser, realmSet);
        Settings settings = Settings.apply(KEYCLOAK_PORT,"0.0.0.0", "/tmp/embedded-keycloak/", true, false, KEYCLOAK_VERSION, true);
        EmbeddedKeycloak embeddedKeycloak = new EmbeddedKeycloak(data, settings);
        Future<StopHandle> stopHandleFuture = embeddedKeycloak.startServer(ExecutionContext.global());
        stopHandle = Await.result(stopHandleFuture, Duration.apply(60, TimeUnit.SECONDS));
    }


    @AfterAll
    void cleanUp() {
        stopHandle.stop();
    }


    // This test does not yet make assertions on "aud" because the resulting token does not have an audience
    @Test
    public void testVerificationPasses() throws Exception {
        // Create an admin client and get token
        Keycloak adminClient = Keycloak.getInstance(KEYCLOAK_URL, "master", "admin", "admin", "admin-cli");
        AccessTokenResponse response = adminClient.tokenManager().getAccessToken();

        // Set up provider
        AuthenticationProviderOpenID provider = new AuthenticationProviderOpenID();
        Properties props = new Properties();
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_TOKEN_ISSUERS, KEYCLOAK_MASTER_REALM_URL);
        props.setProperty(AuthenticationProviderOpenID.ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN, "false");
        props.setProperty(AuthenticationProviderOpenID.REQUIRE_HTTPS, "false");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        provider.initialize(config);

        Assertions.assertDoesNotThrow(() -> provider.authenticate(new AuthenticationDataCommand(response.getToken())));
    }

    @Test
    public void testVerificationFailsForIssuer() throws Exception {
        // Create an admin client and get token
        Keycloak adminClient = Keycloak.getInstance(KEYCLOAK_URL, "master", "admin", "admin", "admin-cli");
        AccessTokenResponse response = adminClient.tokenManager().getAccessToken();

        AuthenticationProviderOpenID provider = new AuthenticationProviderOpenID();

        Properties props = new Properties();
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_TOKEN_ISSUERS, "http://localhost:8081/");
        props.setProperty(AuthenticationProviderOpenID.ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN, "false");
        props.setProperty(AuthenticationProviderOpenID.REQUIRE_HTTPS, "false");

        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);

        provider.initialize(config);

        Assertions.assertThrows(AuthenticationException.class,
                () -> provider.authenticate(new AuthenticationDataCommand(response.getToken())));
    }

    @Test
    public void testVerificationFailsForIncorrectAudience() throws Exception {
        // Create an admin client and get token
        Keycloak adminClient = Keycloak.getInstance(KEYCLOAK_URL, "master", "admin", "admin", "admin-cli");
        AccessTokenResponse response = adminClient.tokenManager().getAccessToken();

        AuthenticationProviderOpenID provider = new AuthenticationProviderOpenID();

        // Include valid issuer and invalid audience
        Properties props = new Properties();
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_TOKEN_ISSUERS, KEYCLOAK_MASTER_REALM_URL);
        props.setProperty(AuthenticationProviderOpenID.ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN, "false");
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_AUDIENCE, "missing_audience");
        props.setProperty(AuthenticationProviderOpenID.REQUIRE_HTTPS, "false");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);

        provider.initialize(config);

        Assertions.assertThrows(AuthenticationException.class,
                () -> provider.authenticate(new AuthenticationDataCommand(response.getToken())));
    }

    @Test
    void testAuthStateBehavesAsExpected() throws Exception {
        // Create an admin client and get token
        Keycloak adminClient = Keycloak.getInstance(KEYCLOAK_URL, "master", "admin", "admin", "admin-cli");
        AccessTokenResponse response = adminClient.tokenManager().getAccessToken();

        // Set up the provider
        AuthenticationProviderOpenID provider = new AuthenticationProviderOpenID();
        Properties props = new Properties();
        props.setProperty(AuthenticationProviderOpenID.ACCEPTED_TIME_LEEWAY_SECONDS, "10");
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_TOKEN_ISSUERS, KEYCLOAK_MASTER_REALM_URL);
        props.setProperty(AuthenticationProviderOpenID.ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN, "false");
        props.setProperty(AuthenticationProviderOpenID.REQUIRE_HTTPS, "false");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        provider.initialize(config);

        // Set up auth data
        AuthData authData = AuthData.of(response.getToken().getBytes(StandardCharsets.UTF_8));

        AuthenticationState authState = null;
        try {
            authState = provider.newAuthState(authData, null, null);
        } catch (AuthenticationException e) {
            Assertions.fail(e);
        }
        // We just got the token, so authState should be complete immediately and it shouldn't be expired
        Assertions.assertTrue(authState.isComplete());
        Assertions.assertFalse(authState.isExpired());
    }

    @Test
    void testInvalidTokenWithValidIssuer() throws Exception {
        // Set up the provider
        AuthenticationProviderOpenID provider = new AuthenticationProviderOpenID();
        Properties props = new Properties();
        props.setProperty(AuthenticationProviderOpenID.ACCEPTED_TIME_LEEWAY_SECONDS, "10");
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_TOKEN_ISSUERS, KEYCLOAK_MASTER_REALM_URL);
        props.setProperty(AuthenticationProviderOpenID.ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN, "false");
        props.setProperty(AuthenticationProviderOpenID.REQUIRE_HTTPS, "false");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        provider.initialize(config);

        // Set up a token that isn't valid, but has a valid issuer to ensure we call the token provider
        // and then fail on the algorithm portion.
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        DefaultJwtBuilder defaultJwtBuilder = new DefaultJwtBuilder();
        defaultJwtBuilder.setIssuer(KEYCLOAK_MASTER_REALM_URL);
        defaultJwtBuilder.signWith(keyPair.getPrivate());

        Assertions.assertThrows(AuthenticationException.class,
                () -> provider.authenticate(new AuthenticationDataCommand(defaultJwtBuilder.compact())));
    }
}
