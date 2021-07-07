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
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.*;
import org.apache.pulsar.common.api.AuthData;

import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.*;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.datastax.oss.pulsar.auth.ConfigUtils.*;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;


/**
 * An {@link AuthenticationProvider} implementation that supports the usage of a JSON Web Token (JWT)
 * for client authentication. This implementation retrieves the PublicKey from the JWT issuer (assuming the
 * issuer is in the configured allowed list) and then uses that Public Key to verify the validity of the JWT's
 * signature.
 *
 * The Public Keys for a given provider are cached based on certain configured parameters to improve performance.
 * The tradeoff here is that the longer Public Keys are cached, the longer an invalidated token could be used. Once way
 * to ensure caches are cleared is to restart all brokers.
 *
 * Class is called from multiple threads. The implementation must be thread safe. This class expects to be loaded once
 * and then called concurrently for each new connection. The caches is backed by a GuavaCachedJwkProvider, which is
 * thread-safe.
 *
 * Supported algorithms are: RS256, RS384, RS512, ES256, ES384, ES512 where the naming conventions follow
 * this RFC: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1.
 */
public class AuthenticationProviderOpenID implements AuthenticationProvider {

    // This is backed by an ObjectMapper, which is thread safe. It is an optimization
    // to share this for decoding JWTs for all connections to this broker.
    private final JWT jwtLibrary = new JWT();

    // A map from issuer to JwkProvider.
    // A broker loads a single provider once, so this map is shared across all connections.
    // That means the caching in each JwkProvider is broker wide.
    private Map<String, JwkProvider> issuerToJwkProviders;

    private AuthenticationProviderToken authenticationProviderToken = new AuthenticationProviderToken();

    // A list of supported algorithms. This is the "alg" field on the JWT.
    // Source for strings: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1.
    private static final String ALG_RS256 = "RS256";
    private static final String ALG_RS384 = "RS384";
    private static final String ALG_RS512 = "RS512";
    private static final String ALG_ES256 = "ES256";
    private static final String ALG_ES384 = "ES384";
    private static final String ALG_ES512 = "ES512";

    // For now, Keycloak is supported (and any other identity providers that follow the same endpoint pattern)
    // Eventually, it'd be good to discover the `jwks_uri` via the ".well-known/openid-configuration"
    // endpoint (this is part of the OpenID Connect spec
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata), which provides a uri to discover
    // the JWKs and can be used for multiple identity providers.
    private static final String KEYCLOAK_JWKS_ENDPOINT = "/protocol/openid-connect/certs";

    private long acceptedTimeLeeway; // seconds
    private boolean isAttemptAuthenticationProviderTokenFirst;

    static final String ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN_FIRST = "openIDAttemptAuthenticationProviderTokenFirst";
    static final String ALLOWED_TOKEN_ISSUERS = "openIDAllowedTokenIssuers";
    static final String ALLOWED_AUDIENCE = "openIDAllowedAudience";
    static final String ACCEPTED_TIME_LEEWAY_SECONDS = "openIDAcceptedTimeLeewaySeconds";
    static final String JWK_CACHE_SIZE = "openIDJwkCacheSize";
    static final String JWK_EXPIRES_MINUTES = "openIDJwkExpiresMinutes";

    private String audience;

    @Override
    public void initialize(ServiceConfiguration config) throws IOException {
        this.audience = getConfigValueAsString(config, ALLOWED_AUDIENCE);
        this.acceptedTimeLeeway = getConfigValueAsLong(config, ACCEPTED_TIME_LEEWAY_SECONDS, 0);
        long cacheSize = getConfigValueAsLong(config, JWK_CACHE_SIZE, 10);
        long jwkExpiresInMin = getConfigValueAsLong(config, JWK_EXPIRES_MINUTES, 5);
        Map<String, JwkProvider> tmpMap = new HashMap<>();
        Set<String> issuers = getConfigValueAsSet(config, ALLOWED_TOKEN_ISSUERS);
        if (issuers.isEmpty()) {
            throw new IllegalArgumentException("Missing configured value for: " + ALLOWED_TOKEN_ISSUERS);
        }
        issuers.forEach(issuer -> {
            URL url = urlForDomain(issuer);
            JwkProvider baseProvider = new UrlJwkProvider(url);
            JwkProvider cache = new GuavaCachedJwkProvider(baseProvider, cacheSize, jwkExpiresInMin, TimeUnit.MINUTES);
            tmpMap.put(issuer, cache);
        });
        issuerToJwkProviders = Collections.unmodifiableMap(tmpMap);

        this.isAttemptAuthenticationProviderTokenFirst =
                getConfigValueAsBoolean(config, ATTEMPT_AUTHENTICATION_PROVIDER_TOKEN_FIRST, true);

        if (isAttemptAuthenticationProviderTokenFirst) {
            // Set up the fallback token authentication provider
            this.authenticationProviderToken.initialize(config);
        }
    }

    @Override
    public String getAuthMethodName() {
        // Intentionally matches AuthenticationProviderToken.TOKEN
        return "token";
    }

    /**
     * Authenticate
     *
     * Note that if the authentication fails for the {@link AuthenticationProviderToken}, it will increment
     * failure metrics even though the authentication may succeed on the OpenID Connect authentication step.
     *
     * TODO evaluate creating a better mechanism here, like using a JWT claim to indicate which method to use.
     *
     * @param authData - the authData passed by the Pulsar Broker containing the token.
     * @return the role, if the JWT is authenticated
     * @throws AuthenticationException if the JWT is invalid
     */
    @Override
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        if (isAttemptAuthenticationProviderTokenFirst) {
            try {
                return this.authenticationProviderToken.authenticate(authData);
            } catch (AuthenticationException ignored) {
                // Ignore failure and attempt
            }
        }
        String token = AuthenticationProviderToken.getToken(authData);
        DecodedJWT validatedJWT = authenticateToken(token);
        return getRole(validatedJWT);
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
     * @throws AuthenticationException if the token string is invalid
     */
    public DecodedJWT decodeJWT(String token) throws AuthenticationException {
        try {
            return jwtLibrary.decodeJwt(token);
        } catch (JWTDecodeException e) {
            throw new AuthenticationException("Unable to decode JWT: " + e.getMessage());
        }
    }

    public DecodedJWT authenticateToken(String token) throws AuthenticationException {
        try {
            if (token == null) {
                throw new AuthenticationException("Invalid token: cannot be null");
            }
            DecodedJWT jwt = decodeJWT(token);
            Jwk jwk = verifyIssuerAndGetJwk(jwt);
            // Throws exception if any verification check fails
            return verifyJWT(jwk.getPublicKey(), jwk.getAlgorithm(), jwt);
        } catch (JWTVerificationException | InvalidPublicKeyException e) {
            throw new AuthenticationException("JWT verification failed: " + e.getMessage());
        }
    }

    public Jwk verifyIssuerAndGetJwk(DecodedJWT jwt) throws AuthenticationException {
        if (jwt.getIssuer() == null) {
            throw new AuthenticationException("Issuer cannot be null");
        }
        // The issuerToJwkProviders map contains all valid issuers. This get
        // verifies that the "iss" on the token is in the approved list of issuers.
        JwkProvider jwkProvider = issuerToJwkProviders.get(jwt.getIssuer());
        if (jwkProvider == null) {
            throw new AuthenticationException("Invalid issuer: " + jwt.getIssuer());
        }
        try {
            return jwkProvider.get(jwt.getKeyId());
        } catch (JwkException e) {
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
                    throw new AuthenticationException("Unsupported algorithm: " + publicKeyAlg);
            }
        } catch (ClassCastException e) {
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
        } catch (JWTVerificationException e) {
            throw new AuthenticationException("JWT verification failed: " + e.getMessage());
        }
    }

    static URL urlForDomain(String domain) {
        checkArgument(!isNullOrEmpty(domain), "A domain is required");

        // Per this RFC, https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2,
        // this transport should be TLS, but if the broker's configuration has an
        // http prefix, we allow the configuration to work. This may change in the future
        // to prevent accidental retrieval of PublicKeys in an insecure way.
        if (!domain.startsWith("http")) {
            domain = "https://" + domain;
        }

        try {
            final URI uri = new URI(domain + KEYCLOAK_JWKS_ENDPOINT).normalize();
            return uri.toURL();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new IllegalArgumentException("Invalid JWKS uri", e);
        }
    }
}
