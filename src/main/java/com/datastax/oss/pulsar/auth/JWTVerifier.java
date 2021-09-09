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
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.naming.AuthenticationException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class JWTVerifier {

    // A list of supported algorithms. This is the "alg" field on the JWT.
    // Source for strings: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1.
    private static final String ALG_RS256 = "RS256";
    private static final String ALG_RS384 = "RS384";
    private static final String ALG_RS512 = "RS512";
    private static final String ALG_ES256 = "ES256";
    private static final String ALG_ES384 = "ES384";
    private static final String ALG_ES512 = "ES512";

    private final long acceptedTimeLeeway;
    private final String audience;

    JWTVerifier(long acceptedTimeLeeway, String audience) {
        this.acceptedTimeLeeway = acceptedTimeLeeway;
        this.audience = audience;
    }

    /**
     * Verify the JWT using the parameterized Public Key.
     *
     * @param publicKey - the public key to use when validating the JWT's signature.
     * @param jwt - jwt to be verified
     * @throws AuthenticationException if the Public Key's algorithm is not supported or if the algorithm param does not
     * match the Public Key's actual algorithm.
     */
    public void verifyJWT(PublicKey publicKey, DecodedJWT jwt) throws AuthenticationException {
        Algorithm alg = getAlgorithm(publicKey, jwt.getAlgorithm());
        // We verify issuer when retrieving the PublicKey, so it is not verified here
        // If the configured audience is null, there is no check for the "aud" claim.
        com.auth0.jwt.interfaces.JWTVerifier verifier = JWT.require(alg)
                .acceptLeeway(acceptedTimeLeeway)
                .withAudience(audience)
                .build();

        try {
            verifier.verify(jwt);
        } catch (TokenExpiredException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.EXPIRED_JWT);
            throw new AuthenticationException("JWT expired: " + e.getMessage());
        } catch (SignatureVerificationException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.ERROR_VERIFYING_JWT_SIGNATURE);
            throw new AuthenticationException("JWT signature verification exception: " + e.getMessage());
        } catch (InvalidClaimException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.INVALID_JWT_CLAIM);
            throw new AuthenticationException("JWT contains invalid claim: " + e.getMessage());
        } catch (AlgorithmMismatchException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.ALGORITHM_MISMATCH);
            throw new AuthenticationException("JWT algorithm does not match Public Key algorithm: " + e.getMessage());
        } catch (JWTDecodeException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.ERROR_DECODING_JWT);
            throw new AuthenticationException("Error while decoding JWT: " + e.getMessage());
        } catch (JWTVerificationException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.ERROR_VERIFYING_JWT);
            throw new AuthenticationException("JWT verification failed: " + e.getMessage());
        }
    }

    public static Algorithm getAlgorithm(PublicKey publicKey, String alg) throws AuthenticationException {
        if (alg == null) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.UNSUPPORTED_ALGORITHM);
            throw new AuthenticationException("Algorithm cannot be null");
        }
        try {
            switch (alg) {
                case ALG_RS256:
                    return Algorithm.RSA256((RSAPublicKey) publicKey, null);
                case ALG_RS384:
                    return Algorithm.RSA384((RSAPublicKey) publicKey, null);
                case ALG_RS512:
                    return Algorithm.RSA512((RSAPublicKey) publicKey, null);
                case ALG_ES256:
                    return Algorithm.ECDSA256((ECPublicKey) publicKey, null);
                case ALG_ES384:
                    return Algorithm.ECDSA384((ECPublicKey) publicKey, null);
                case ALG_ES512:
                    return Algorithm.ECDSA512((ECPublicKey) publicKey, null);
                default:
                    AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.UNSUPPORTED_ALGORITHM);
                    throw new AuthenticationException("Unsupported algorithm: " + alg);
            }
        } catch (ClassCastException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.ALGORITHM_MISMATCH);
            throw new AuthenticationException("JWT alg [" + alg + "] does match PublicKey alg.");
        }
    }

}
