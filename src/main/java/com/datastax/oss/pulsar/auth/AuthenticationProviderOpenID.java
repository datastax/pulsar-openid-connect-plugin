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

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.datastax.oss.pulsar.auth.model.OpenIDProviderMetadata;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.*;
import org.apache.pulsar.broker.authentication.metrics.AuthenticationMetrics;
import org.apache.pulsar.common.api.AuthData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.*;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static com.datastax.oss.pulsar.auth.ConfigUtils.*;


/**
 * An {@link AuthenticationProvider} implementation that supports the usage of a JSON Web Token (JWT)
 * for client authentication. This implementation retrieves the PublicKey from the JWT issuer (assuming the
 * issuer is in the configured allowed list) and then uses that Public Key to verify the validity of the JWT's
 * signature.
 *
 * The Public Keys for a given provider are cached based on certain configured parameters to improve performance.
 * The tradeoff here is that the longer Public Keys are cached, the longer an invalidated token could be used. One way
 * to ensure caches are cleared is to restart all brokers.
 *
 * Class is called from multiple threads. The implementation must be thread safe. This class expects to be loaded once
 * and then called concurrently for each new connection. The cache is backed by a GuavaCachedJwkProvider, which is
 * thread-safe.
 *
 * Supported algorithms are: RS256, RS384, RS512, ES256, ES384, ES512 where the naming conventions follow
 * this RFC: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1.
 */
public class AuthenticationProviderOpenID implements AuthenticationProvider {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationProviderOpenID.class);

    private static final String SIMPLE_NAME = AuthenticationProviderOpenID.class.getSimpleName();

    // This is backed by an ObjectMapper, which is thread safe. It is an optimization
    // to share this for decoding JWTs for all connections to this broker.
    private final JWT jwtLibrary = new JWT();

    private Set<String> issuers;

    // This caches the map from Issuer URL to the jwks_uri served at the /.well-known/openid-configuration endpoint
    private OpenIDProviderMetadataCache openIDProviderMetadataCache;

    // A map from the jwks_uri for an issuer to GuavaCachedJwkProvider.
    // A broker loads a single provider once, so this map is shared across all connections.
    // As a result, the caching in each JwkProvider is broker wide.
    // This map is bounded by the number of allow listed issuers.
    private final Map<URL, GuavaCachedJwkProvider> issuerToJwkProviders = new ConcurrentHashMap<>();

    private AuthenticationProviderToken authenticationProviderToken;

    // A list of supported algorithms. This is the "alg" field on the JWT.
    // Source for strings: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1.
    private static final String ALG_RS256 = "RS256";
    private static final String ALG_RS384 = "RS384";
    private static final String ALG_RS512 = "RS512";
    private static final String ALG_ES256 = "ES256";
    private static final String ALG_ES384 = "ES384";
    private static final String ALG_ES512 = "ES512";

    private long acceptedTimeLeeway; // seconds
    private boolean isAttemptAuthenticationProviderToken;
    private int jwkCacheSize;
    private int jwkExpiresSeconds;
    private int jwkConnectionTimeout;
    private int jwkReadTimeout;
    private boolean requireHttps;

    static final String ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN = "openIDAttemptAuthenticationProviderToken";
    static final String ALLOWED_TOKEN_ISSUERS = "openIDAllowedTokenIssuers";
    static final String ALLOWED_AUDIENCE = "openIDAllowedAudience";
    static final String ACCEPTED_TIME_LEEWAY_SECONDS = "openIDAcceptedTimeLeewaySeconds";
    static final String JWK_CACHE_SIZE = "openIDJwkCacheSize";
    static final String JWK_EXPIRES_SECONDS = "openIDJwkExpiresSeconds";
    static final String JWK_CONNECTION_TIMEOUT_MILLIS = "openIDJwkConnectionTimeoutMillis";
    static final String JWK_READ_TIMEOUT_MILLIS = "openIDJwkReadTimeoutMillis";
    static final String METADATA_CACHE_SIZE = "openIDMetadataCacheSize";
    static final String METADATA_EXPIRES_SECONDS = "openIDMetadataExpiresSeconds";
    static final String METADATA_CONNECTION_TIMEOUT_MILLIS = "openIDMetadataConnectionTimeoutMillis";
    static final String METADATA_READ_TIMEOUT_MILLIS = "openIDMetadataReadTimeoutMillis";
    static final String REQUIRE_HTTPS = "openIDRequireHttps";

    private String audience;

    @Override
    public void initialize(ServiceConfiguration config) throws IOException {
        this.audience = getConfigValueAsString(config, ALLOWED_AUDIENCE);
        this.acceptedTimeLeeway = getConfigValueAsInt(config, ACCEPTED_TIME_LEEWAY_SECONDS, 0);
        this.jwkCacheSize = getConfigValueAsInt(config, JWK_CACHE_SIZE, 10);
        this.jwkExpiresSeconds = getConfigValueAsInt(config, JWK_EXPIRES_SECONDS, 5);
        this.jwkConnectionTimeout = getConfigValueAsInt(config, JWK_CONNECTION_TIMEOUT_MILLIS, 10_000);
        this.jwkReadTimeout = getConfigValueAsInt(config, JWK_READ_TIMEOUT_MILLIS, 10_000);

        this.requireHttps = getConfigValueAsBoolean(config, REQUIRE_HTTPS, true);
        this.issuers = getConfigValueAsSet(config, ALLOWED_TOKEN_ISSUERS);
        validateIssuers(this.issuers);

        int metadataCacheSize = getConfigValueAsInt(config, METADATA_CACHE_SIZE, 10);
        int metadataExpiresHours = getConfigValueAsInt(config, METADATA_EXPIRES_SECONDS, 24);
        int metadataConnectionTimeout = getConfigValueAsInt(config, METADATA_CONNECTION_TIMEOUT_MILLIS, 10_000);
        int metadataReadTimeout = getConfigValueAsInt(config, METADATA_READ_TIMEOUT_MILLIS, 10_000);
        this.openIDProviderMetadataCache = new OpenIDProviderMetadataCache(metadataCacheSize, metadataExpiresHours,
                metadataConnectionTimeout, metadataReadTimeout);

        this.isAttemptAuthenticationProviderToken =
                getConfigValueAsBoolean(config, ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN, true);
        if (isAttemptAuthenticationProviderToken) {
            // Set up the fallback token authentication provider
            this.authenticationProviderToken = new AuthenticationProviderToken();
            this.authenticationProviderToken.initialize(config);
        }
    }

    @Override
    public String getAuthMethodName() {
        // Intentionally matches AuthenticationProviderToken.TOKEN
        return "token";
    }

    /**
     * Authenticate the parameterized {@link AuthenticationDataSource}.
     *
     * If the {@link AuthenticationProviderToken} is enabled and the JWT does not have an Issuer ("iss") claim,
     * this class will use the {@link AuthenticationProviderToken} to verify/authenticate the token. See the
     * documentation for {@link AuthenticationProviderToken} regarding configuration.
     *
     * Otherwise, this class will verify/authenticate the token by retrieving the Public key from allow listed issuers.
     *
     * @param authData - the authData passed by the Pulsar Broker containing the token.
     * @return the role, if the JWT is authenticated
     * @throws AuthenticationException if the JWT is invalid
     */
    @Override
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String token;
        try {
            token = AuthenticationProviderToken.getToken(authData);
        } catch (AuthenticationException e) {
            // To see the stack trace, turn on debug logging.
            log.warn(String.format("Authentication failed for request from remote ip [%s] with reason: %s",
                    authData.getPeerAddress(), e.getMessage()));
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_DECODING_JWT);
            throw e;
        }
        // Token is only decoded at this point. It is not yet verified.
        DecodedJWT jwt = decodeJWT(token);
        if (isAttemptAuthenticationProviderToken && jwt.getIssuer() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Issuer claim is null. Attempting token authentication using AuthenticationProviderToken.");
            }
            // The method is instrumented internally, so no metrics are recorded here.
            return this.authenticationProviderToken.authenticate(authData);
        } else {
            try {
                DecodedJWT validatedJWT = authenticateToken(jwt);
                String role = getRole(validatedJWT);
                log.info(String.format("Authentication succeeded for request from remote ip [%s] for role [%s]",
                        role, authData.getPeerAddress()));
                AuthenticationMetrics.authenticateSuccess(getClass().getSimpleName(), getAuthMethodName());
                return role;
            } catch (AuthenticationException e) {
                // To see the stack trace, turn on debug logging.
                log.warn(String.format("Authentication failed for request from remote ip [%s] with reason: %s",
                        authData.getPeerAddress(), e.getMessage()));
                // Failure metrics are incremented within methods above
                throw e;
            }
        }
    }

    /**
     * For now, the role is the subject (or the "sub" field) from the JWT
     * @param jwt - token to get the role from
     */
    public String getRole(DecodedJWT jwt) {
        return jwt.getSubject();
    }

    /**
     * Convert a JWT string into a {@link DecodedJWT}
     * The benefit of using this method is that it utilizes the already instantiated {@link JWT} parser.
     * WARNING: this method does not verify the authenticity of the token. It only decodes it.
     *
     * @param token - string JWT to be decoded
     * @return a decoded JWT
     * @throws AuthenticationException if the token string is null or if any part of the token contains
     *         an invalid jwt or JSON format of each of the jwt parts.
     */
    public DecodedJWT decodeJWT(String token) throws AuthenticationException {
        if (token == null) {
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_DECODING_JWT);
            throw new AuthenticationException("Invalid token: cannot be null");
        }
        try {
            return jwtLibrary.decodeJwt(token);
        } catch (JWTDecodeException e) {
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_DECODING_JWT);
            throw new AuthenticationException("Unable to decode JWT: " + e.getMessage());
        }
    }

    /**
     * Authenticate the parameterized JWT.
     *
     * @param jwt - a nonnull JWT to authenticate
     * @return a fully authenticated JWT
     * @throws AuthenticationException if the JWT is proven to be invalid in any way
     */
    public DecodedJWT authenticateToken(DecodedJWT jwt) throws AuthenticationException {
        if (jwt == null) {
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_DECODING_JWT);
            throw new AuthenticationException("JWT cannot be null");
        }
        try {
            Jwk jwk = verifyIssuerAndGetJwk(jwt);
            // Throws exception if any verification check fails
            return verifyJWT(jwk.getPublicKey(), jwt.getAlgorithm(), jwt);
        } catch (InvalidPublicKeyException e) {
            incrementFailureMetric(AuthenticationExceptionCode.INVALID_PUBLIC_KEY);
            throw new AuthenticationException("Invalid public key: " + e.getMessage());
        }
    }

    public Jwk verifyIssuerAndGetJwk(DecodedJWT jwt) throws AuthenticationException {
        // Verify that the issuer claim is nonnull and allowed.
        if (jwt.getIssuer() == null || !this.issuers.contains(jwt.getIssuer())) {
            incrementFailureMetric(AuthenticationExceptionCode.UNSUPPORTED_ISSUER);
            throw new AuthenticationException("Issuer not allowed: " + jwt.getIssuer());
        }
        // Retrieve the metadata: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        OpenIDProviderMetadata metadata = openIDProviderMetadataCache.getOpenIDProviderMetadataForIssuer(jwt.getIssuer());
        JwkProvider jwkProvider = getJwkProviderForIssuer(metadata.getJwksUri());
        try {
            return jwkProvider.get(jwt.getKeyId());
        } catch (JwkException e) {
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_RETRIEVING_PUBLIC_KEY);
            throw new AuthenticationException("Unable to retrieve PublicKey: " + e.getMessage());
        }
    }

    @Override
    public AuthenticationState newAuthState(AuthData authData, SocketAddress remoteAddress, SSLSession sslSession)
            throws AuthenticationException {
        return new AuthenticationStateOpenID(this, authData, remoteAddress, sslSession);
    }

    /**
     * Closes this stream and releases any system resources associated
     * with it. If the stream is already closed then invoking this
     * method has no effect.
     *
     * <p> As noted in {@link AutoCloseable#close()}, cases where the
     * close may fail require careful attention. It is strongly advised
     * to relinquish the underlying resources and to internally
     * <em>mark</em> the {@code Closeable} as closed, prior to throwing
     * the {@code IOException}.
     *
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void close() throws IOException {
        // noop
    }

    /**
     * Build and return a validator for the parameters.
     *
     * @param publicKey - the public key to use when configuring the validator
     * @param publicKeyAlg - the algorithm for the parameterized public key
     * @param jwt - jwt to be verified and returned (only if verified)
     * @return a validator to use for validating a JWT associated with the parameterized public key.
     * @throws AuthenticationException if the Public Key's algorithm is not supported or if the algorithm param does not
     * match the Public Key's actual algorithm.
     */
    public DecodedJWT verifyJWT(PublicKey publicKey, String publicKeyAlg, DecodedJWT jwt) throws AuthenticationException {
        if (publicKeyAlg == null) {
            incrementFailureMetric(AuthenticationExceptionCode.UNSUPPORTED_ALGORITHM);
            throw new AuthenticationException("PublicKey algorithm cannot be null");
        }

        Algorithm alg;
        try {
            switch (publicKeyAlg) {
                case ALG_RS256:
                    alg = Algorithm.RSA256((RSAPublicKey) publicKey, null);
                    break;
                case ALG_RS384:
                    alg = Algorithm.RSA384((RSAPublicKey) publicKey, null);
                    break;
                case ALG_RS512:
                    alg = Algorithm.RSA512((RSAPublicKey) publicKey, null);
                    break;
                case ALG_ES256:
                    alg = Algorithm.ECDSA256((ECPublicKey) publicKey, null);
                    break;
                case ALG_ES384:
                    alg = Algorithm.ECDSA384((ECPublicKey) publicKey, null);
                    break;
                case ALG_ES512:
                    alg = Algorithm.ECDSA512((ECPublicKey) publicKey, null);
                    break;
                default:
                    incrementFailureMetric(AuthenticationExceptionCode.UNSUPPORTED_ALGORITHM);
                    throw new AuthenticationException("Unsupported algorithm: " + publicKeyAlg);
            }
        } catch (ClassCastException e) {
            incrementFailureMetric(AuthenticationExceptionCode.ALGORITHM_MISMATCH);
            throw new AuthenticationException("Expected PublicKey alg [" + publicKeyAlg + "] does match actual alg.");
        }

        // We verify issuer when retrieving the PublicKey, so it is not verified here
        // If the configured audience is null, there is no check for the "aud" claim.
        JWTVerifier verifier = JWT.require(alg)
                .acceptLeeway(acceptedTimeLeeway)
                .withAudience(audience)
                .build();

        try {
            return verifier.verify(jwt);
        } catch (TokenExpiredException e) {
            incrementFailureMetric(AuthenticationExceptionCode.EXPIRED_JWT);
            throw new AuthenticationException("JWT expired: " + e.getMessage());
        } catch (SignatureVerificationException e) {
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_VERIFYING_JWT_SIGNATURE);
            throw new AuthenticationException("JWT signature verification exception: " + e.getMessage());
        } catch (InvalidClaimException e) {
            incrementFailureMetric(AuthenticationExceptionCode.INVALID_JWT_CLAIM);
            throw new AuthenticationException("JWT contains invalid claim: " + e.getMessage());
        } catch (AlgorithmMismatchException e) {
            incrementFailureMetric(AuthenticationExceptionCode.ALGORITHM_MISMATCH);
            throw new AuthenticationException("JWT algorithm does not match Public Key algorithm: " + e.getMessage());
        } catch (JWTDecodeException e) {
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_DECODING_JWT);
            throw new AuthenticationException("Error while decoding JWT: " + e.getMessage());
        } catch (JWTVerificationException e) {
            incrementFailureMetric(AuthenticationExceptionCode.ERROR_VERIFYING_JWT);
            throw new AuthenticationException("JWT verification failed: " + e.getMessage());
        }
    }

    private JwkProvider getJwkProviderForIssuer(URL issuer) {
        return issuerToJwkProviders.computeIfAbsent(issuer, (iss) -> {
            JwkProvider baseProvider = new UrlJwkProvider(iss, this.jwkConnectionTimeout, this.jwkReadTimeout);
            return new GuavaCachedJwkProvider(baseProvider, this.jwkCacheSize, this.jwkExpiresSeconds, TimeUnit.SECONDS);
        });
    }

    static void incrementFailureMetric(AuthenticationExceptionCode code) {
        AuthenticationMetrics.authenticateFailure(SIMPLE_NAME, "token", code.toString());
    }

    /**
     * Validate the configured allow list of allowedIssuers. The allowedIssuers set must be nonempty in order for
     * the plugin to authenticate any token. Thus, it fails initialization if the configuration is
     * missing. Each issuer URL should use the HTTPS scheme. The plugin fails initialization if any
     * issuer url is insecure, unless {@link AuthenticationProviderOpenID#REQUIRE_HTTPS} is
     * configured to false.
     * @param allowedIssuers - issuers to validate
     * @throws IllegalArgumentException if the allowedIssuers is empty, or contains insecure issuers when required
     */
    void validateIssuers(Set<String> allowedIssuers) {
        if (allowedIssuers.isEmpty()) {
            throw new IllegalArgumentException("Missing configured value for: " + ALLOWED_TOKEN_ISSUERS);
        }
        for (String issuer : allowedIssuers) {
            if (!issuer.toLowerCase().startsWith("https://")) {
                log.warn("Allowed issuer is not using https scheme: {}", issuer);
                if (requireHttps) {
                    throw new IllegalArgumentException("Issuer URL does not use https, but must: " + issuer);
                }
            }
        }
    }
}
