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

import com.datastax.oss.pulsar.auth.model.OpenIDProviderMetadata;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;

import javax.annotation.Nonnull;
import javax.naming.AuthenticationException;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Class used to cache metadata responses from OpenID Providers
 */
class OpenIDProviderMetadataCache {

    private final ObjectReader reader = new ObjectMapper().readerFor(OpenIDProviderMetadata.class);

    private final int connectionTimeout;
    private final int readTimeout;

    private final CacheLoader<String, OpenIDProviderMetadata> loader = new CacheLoader<>() {
        @Override
        public OpenIDProviderMetadata load(@Nonnull String issuer) throws Exception {
            URLConnection urlConnection = createUrlConnection(issuer);
            try (InputStream inputStream = urlConnection.getInputStream()) {
                OpenIDProviderMetadata openIDProviderMetadata = reader.readValue(inputStream);
                verifyIssuer(issuer, openIDProviderMetadata);
                return openIDProviderMetadata;
            } catch (IOException e) {
                AuthenticationProviderOpenID.incrementFailureMetric(
                        AuthenticationExceptionCode.ERROR_RETRIEVING_PROVIDER_METADATA);
                throw new AuthenticationException("Error retrieving OpenID Provider Metadata: " + e.getMessage());
            }
        }
    };

    private final LoadingCache<String, OpenIDProviderMetadata> cache;

    OpenIDProviderMetadataCache(int maxSize, int expireAfterHours, int connectionTimeout, int readTimeout) {
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;
        this.cache = CacheBuilder.newBuilder()
                .maximumSize(maxSize)
                .expireAfterWrite(expireAfterHours, TimeUnit.HOURS)
                .build(loader);
    }

    /**
     * Retrieve the OpenID Provider Metadata for the provided issuer.
     *
     * Note: this method does not do any validation on the parameterized issuer. The OpenID Connect discovery
     * spec requires that the issuer use the HTTPS scheme: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata.
     * The {@link AuthenticationProviderOpenID} class handles this verification.
     *
     * @param issuer - authority from which to retrieve the OpenID Provider Metadata
     * @return the {@link OpenIDProviderMetadata} for the given issuer
     * @throws AuthenticationException if any exceptions occur while retrieving the metadata.
     */
    public OpenIDProviderMetadata getOpenIDProviderMetadataForIssuer(String issuer) throws AuthenticationException {
        if (issuer == null) {
            throw new IllegalArgumentException("Issuer must not be null.");
        }
        try {
            return cache.get(issuer);
        } catch (ExecutionException | UncheckedExecutionException e) {
            // Metrics are recorded in the CacheLoader
            if (e.getCause() instanceof AuthenticationException) {
                throw (AuthenticationException) e.getCause();
            }
            throw new AuthenticationException("Error retrieving OpenID Provider Metadata: " + e.getMessage());
        }
    }

    /**
     * Create a url connection to the issuer.
     * @param issuer - the issuer to connect to
     * @return a connection to the issuer's /.well-known/openid-configuration endpoint
     * @throws AuthenticationException if the URL is malformed or there is an exception while opening the connection
     */
    private URLConnection createUrlConnection(String issuer) throws AuthenticationException {
        try {
            // TODO URI's normalization follows RFC2396, whereas the spec https://openid.net/specs/openid-connect-discovery-1_0.html#NormalizationSteps
            // calls for normalization according to RFC3986, which is supposed to obsolete RFC2396
            URL issuerMetadataUrl = URI.create(issuer + "/.well-known/openid-configuration").normalize().toURL();
            URLConnection urlConnection = issuerMetadataUrl.openConnection();
            urlConnection.setConnectTimeout(connectionTimeout);
            urlConnection.setReadTimeout(readTimeout);
            return urlConnection;
        } catch (MalformedURLException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(
                    AuthenticationExceptionCode.ERROR_RETRIEVING_PROVIDER_METADATA);
            throw new AuthenticationException("Malformed issuer metadata url: " + e.getMessage());
        } catch (IOException e) {
            AuthenticationProviderOpenID.incrementFailureMetric(
                    AuthenticationExceptionCode.ERROR_RETRIEVING_PROVIDER_METADATA);
            throw new AuthenticationException("Error while opening issuer metadata connection: " + e.getMessage());
        }
    }

    /**
     * Verify the issuer url, as required by the OpenID Connect spec:
     *
     * Per the OpenID Connect Discovery spec, the issuer value returned MUST be identical to the
     * Issuer URL that was directly used to retrieve the configuration information. This MUST also
     * be identical to the iss Claim value in ID Tokens issued from this Issuer.
     * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
     *
     * @param issuer - the issuer used to retrieve the metadata
     * @param metadata - the OpenID Provider Metadata
     * @throws AuthenticationException if the issuer does not exactly match the metadata issuer
     */
    private void verifyIssuer(@Nonnull String issuer, OpenIDProviderMetadata metadata) throws AuthenticationException {
        if (!issuer.equals(metadata.getIssuer())) {
            AuthenticationProviderOpenID.incrementFailureMetric(AuthenticationExceptionCode.ISSUER_MISMATCH);
            throw new AuthenticationException(String.format("Issuer URL mismatch: [%s] should match [%s]",
                    issuer, metadata.getIssuer()));
        }
    }
}
