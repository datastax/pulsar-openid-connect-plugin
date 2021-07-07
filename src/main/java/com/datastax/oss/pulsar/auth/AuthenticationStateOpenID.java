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

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.pulsar.broker.authentication.AuthenticationDataCommand;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationState;
import org.apache.pulsar.common.api.AuthData;

import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import java.net.SocketAddress;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Class representing the authentication state of a single connection.
 */
class AuthenticationStateOpenID implements AuthenticationState {
    private final AuthenticationProviderOpenID provider;
    private AuthenticationDataSource authenticationDataSource;
    // Ensure that all threads get access to the current role
    private volatile String role;
    private final SocketAddress remoteAddress;
    private final SSLSession sslSession;
    private long expiration;

    AuthenticationStateOpenID(
            AuthenticationProviderOpenID provider,
            AuthData authData,
            SocketAddress remoteAddress,
            SSLSession sslSession) throws AuthenticationException {
        this.provider = provider;
        this.remoteAddress = remoteAddress;
        this.sslSession = sslSession;
        this.authenticate(authData);
    }

    @Override
    public String getAuthRole() throws AuthenticationException {
        // Auth completes on initialization, so this never throws an AuthenticationException
        return role;
    }

    @Override
    public AuthData authenticate(AuthData authData) throws AuthenticationException {
        String token = new String(authData.getBytes(), UTF_8);

        this.authenticationDataSource = new AuthenticationDataCommand(token, remoteAddress, sslSession);
        this.role = provider.authenticate(authenticationDataSource);
        // This is a bit inefficient. Ideally we would only decode the JWT once.
        DecodedJWT jwt = provider.decodeJWT(token);
        if (jwt.getExpiresAt() != null) {
            this.expiration = jwt.getExpiresAt().getTime();
        } else {
            // Disable expiration
            this.expiration = Long.MAX_VALUE;
        }

        // There's no additional auth stage required
        return null;
    }

    @Override
    public AuthenticationDataSource getAuthDataSource() {
        return authenticationDataSource;
    }

    @Override
    public boolean isComplete() {
        // The authentication of tokens is always done in one single stage
        return true;
    }

    @Override
    public boolean isExpired() {
        return System.currentTimeMillis() > expiration;
    }
}
