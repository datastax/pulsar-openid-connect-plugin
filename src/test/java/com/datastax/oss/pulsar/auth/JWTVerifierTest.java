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

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.security.Keys;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.naming.AuthenticationException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.Date;
import java.time.Instant;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class JWTVerifierTest {

    // The set of algorithms we expect the AuthenticationProviderOpenID to support
    final Set<SignatureAlgorithm> supportedAlgorithms = Set.of(
            SignatureAlgorithm.RS256, SignatureAlgorithm.RS384, SignatureAlgorithm.RS512,
            SignatureAlgorithm.ES256, SignatureAlgorithm.ES384, SignatureAlgorithm.ES512);

    @Test
    public void testThatUnsupportedAlgsThrowExceptions() {
        Set<SignatureAlgorithm> unsupportedAlgs = new HashSet<>(Set.of(SignatureAlgorithm.values()));
        unsupportedAlgs.removeAll(supportedAlgorithms);
        unsupportedAlgs.forEach(unsupportedAlg -> {
            // We don't create a public key because it's irrelevant
            Assertions.assertThrows(AuthenticationException.class,
                    () -> JWTVerifier.getAlgorithm(null, unsupportedAlg.getValue()));
        });
    }

    @Test
    public void testThatSupportedAlgsWork() {
        supportedAlgorithms.forEach(supportedAlg -> {
            KeyPair keyPair = Keys.keyPairFor(supportedAlg);
            AuthenticationProviderOpenID provider = new AuthenticationProviderOpenID();
            DefaultJwtBuilder defaultJwtBuilder = new DefaultJwtBuilder();
            defaultJwtBuilder.setAudience("an-audience");
            defaultJwtBuilder.signWith(keyPair.getPrivate());

            // Convert to the right class
            DecodedJWT expectedValue = JWT.decode(defaultJwtBuilder.compact());
            JWTVerifier verifier = new JWTVerifier(10, null);
            try {
                verifier.verifyJWT(keyPair.getPublic(), expectedValue);
            } catch (AuthenticationException e) {
                Assertions.fail(e);
            }
        });
    }

    @Test
    public void testThatSupportedAlgWithMismatchedPublicKeyFails() {
        PrivateKey privateKey = Keys.keyPairFor(SignatureAlgorithm.RS256).getPrivate();
        PublicKey publicKey = Keys.keyPairFor(SignatureAlgorithm.ES256).getPublic();
        DefaultJwtBuilder defaultJwtBuilder = new DefaultJwtBuilder();
        defaultJwtBuilder.setAudience("an-audience");
        defaultJwtBuilder.signWith(privateKey);
        DecodedJWT jwt = JWT.decode(defaultJwtBuilder.compact());
        JWTVerifier verifier = new JWTVerifier(10, "an-audience");
        Assertions.assertThrows(AuthenticationException.class, () -> verifier.verifyJWT(publicKey, jwt));
    }

    @Test
    public void ensureExpiredTokenFails() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        DefaultJwtBuilder defaultJwtBuilder = new DefaultJwtBuilder();
        defaultJwtBuilder.setExpiration(Date.from(Instant.EPOCH));
        defaultJwtBuilder.signWith(keyPair.getPrivate());
        DecodedJWT jwt = JWT.decode(defaultJwtBuilder.compact());
        JWTVerifier verifier = new JWTVerifier(10, null);
        Assertions.assertThrows(AuthenticationException.class, () -> verifier.verifyJWT(keyPair.getPublic(), jwt));
    }

    @Test
    public void ensureRecentlyExpiredTokenWithinConfiguredLeewaySucceeds() throws Exception {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);

        // Set up the provider
        AuthenticationProviderOpenID provider = new AuthenticationProviderOpenID();
        Properties props = new Properties();
        props.setProperty(AuthenticationProviderOpenID.ACCEPTED_TIME_LEEWAY_SECONDS, "10");
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_TOKEN_ISSUERS, "https://localhost:8080");
        props.setProperty(AuthenticationProviderOpenID.ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN, "false");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        provider.initialize(config);

        // Build the JWT with an only recently expired token
        DefaultJwtBuilder defaultJwtBuilder = new DefaultJwtBuilder();
        defaultJwtBuilder.setExpiration(Date.from(Instant.ofEpochMilli(System.currentTimeMillis() - 5000L)));
        defaultJwtBuilder.signWith(keyPair.getPrivate());
        DecodedJWT jwt = JWT.decode(defaultJwtBuilder.compact());

        JWTVerifier verifier = new JWTVerifier(10, null);
        // Will throw exception if verification fails
        verifier.verifyJWT(keyPair.getPublic(), jwt);
    }
}
