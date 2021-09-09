# Pulsar OpenID Connect Authentication Plugin

An OpenID Connect implementation of Apache Pulsar's `AuthenticationProvider` and `AuthenticationState` interfaces.

### OpenID Connect

[OpenID Connect](https://openid.net/connect/) is a protocol for identity and authorization. 

This broker side plugin supports the retrieval of Public Keys from an identity provider, like KeyCloak, to support
dynamic validation of JWTs for multiple, configured allowed-listed issuers. It also provides for the ability to first
attempt to use the local `AuthenticationProviderToken` verifier before retrieving a remote JWK for token validation.

### Client Integration
To integrate your client with a broker using this authentication plugin, use Pulsar's built in `AuthenticationToken`
class. Your client application will need to handle retrieving the token as well as refreshing it upon expiration.

### Configuration
The following configuration options are available for this plugin:

| Name | Default Value | Format | Description |
| ---- | ------------- | ------ | ----------- |
| openIDAllowedTokenIssuers | Empty Set | Comma delimited set of URIs | The allowed issuers to trust from the JWT. The `iss` claim must be contained in this set. See [Issuers](#Issuers). |
| openIDAllowedAudience | `null` | String | If not set, defaults to `null`, and the `aud` claim is not checked. If set, the JWT must have the configured `aud` in its claims. If it is missing, the token will be rejected. |
| openIDRoleClaim | `sub` | String | The JWT claim used to get the authenticated token's role. Defaults to the `sub` claim, but can be any claim. |
| openIDAcceptedTimeLeewaySeconds | `0` | Number (no decimals) | The number of seconds that a token will be accepted past its expiration time. |
| openIDJwkCacheSize | `10` | Number (no decimals) | The number of JWK values to keep in the cache. |
| openIDJwkExpiresSeconds | `300` | Number (no decimals) | The length of time, in seconds, to store a JWK before calling the issuer again. Note that this time is also the maximum time that a revoked token can be used. A longer window may improve performance, but it also increases the length of time than a deactivated token could be used. |
| openIDJwkConnectionTimeoutMillis | `10000` | Number (no decimals) | The length of time, in milliseconds, to wait while opening a connection to the JWKS url for an OpenID provider. |
| openIDJwkReadTimeoutMillis | `10000` | Number (no decimals) | The length of time, in milliseconds, to wait for data to be available to read while connected to the OpenID provider. |
| openIDMetadataCacheSize | `10` | Number (no decimals) | The number of OpenID metadata objects to store in the cache. |
| openIDMetadataExpiresSeconds | `86400` | Number (no decimals) | The length of time, in seconds, to store the result of the `/.well-known/openid-configuration` result from an issuer. This result is used to retrieve the issuer's `jwks_uri`, which is then used to retrieve the current public keys for the issuer. |
| openIDMetadataConnectionTimeoutMillis | `10000` | Number (no decimals) | The length of time, in milliseconds, to wait while opening a connection to the issuer's `/.well-known/openid-configuration` endpoint. |
| openIDMetadataReadTimeoutMillis | `10000` | Number (no decimals) | The length of time, in milliseconds, to wait for data to be available to read while connected to the  issuer's `/.well-known/openid-configuration` endpoint. |
| openIDRequireHttps | `true` | Boolean | Whether to fail initialization if the `openIDAllowedTokenIssuers` configuration contains schemes other than `https`. This is provided as a convenience for testing environments. It is strongly recommended, and the OpenID Spec technically requires, using a secure connection when connecting to issuers. |
| openIDAttemptAuthenticationProviderToken | `true` | Boolean | Whether to use the `AuthenticationProviderToken` class when attempting verification of the JWT. See [Using AuthenticationProviderToken](#Using-AuthenticationProviderToken). |

Note that the only required configuration is the `openIDAllowedTokenIssuers`.

### Supported Algorithms
Here is a list of supported algorithms for the OpenID Connect auth plugin: RS256, RS384, RS512, ES256, ES384, ES512.
The algorithm names follow the spec in [RFC-7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1).

### Role Claim
The JWT claim used to retrieve the role is `sub`, by default. If required, you can change the claim by configuring the
`openIDRoleClaim`. Note that this library can handle roles that are a String (JSON text) or Arrays of Strings. In the
case that the JSON node is an Array, this library retrieves the first element of the array for the role. This could lead
to undefined behavior if the array changes order, so it is recommended to use single element arrays.

### Keycloak

### Issuers
The `openIDAllowedTokenIssuers` configuration is essential when configuring which token issuers can be trusted. It is
required by the OAuth2.0 spec [RFC-8414](https://datatracker.ietf.org/doc/html/rfc8414#section-2) that issuers use
the "https" scheme. This ensures the authenticity of the data received from the Authorization Provider and prevents
the leaking of tokens, which are secrets. By default, this plugin will fail to initialize if there are any allowed
issuers without the "https" scheme. Since it can be helpful during testing to turn this off, it is possible to disable
this verification. Note that this plugin uses the issuer url to first retrieve provider metadata at the
`/.well-known/openid-configuration` endpoint. At this endpoint, the plugin retrieves the `jwks_uri`, which points
to the current public keys for the issuer. The plugin retrieves the public keys located at the `jwks_uri` and caches
them for a configurable amount of time.

Note, also, that the plugin verifies the issuer claim by a direct string equality check, per
[RFC-7519](https://datatracker.ietf.org/doc/html/rfc7519#section-7.3). As such, it is necessary
to make sure that the `iss` claim on your JWT is contained in the `openIDAllowedTokenIssuers` collection.

It is also essential to ensure that the `iss` is reachable by the pulsar broker. If the broker cannot reach the allowed
`iss`, it won't be able to retrieve the Public Key, which is a necessary step in asymmetric key validation. This detail
is especially relevant if you are deploying keycloak outside the kubernetes cluster hosting pulsar or even in a
separate namespace within the same kuberentes cluster.

In the case where your Token Issuer is running in the same kubernetes cluster as pulsar, but the issuer is accessed from
outside that kubernetes cluster, there is a chance that the networking may not be ideal. This is because the issuer will
likely be the FQDN for the Token Issuer, which is likely pointed at a load balancer, which means that when the broker
retrieves the JWK, it will egress the kubernetes cluster, ingress through the load balancer, and then connect to the
Token Issuer. For this reason, it is recommended that applications collocated in the kubernetes cluster with the Token
Issuer and the Pulsar cluster should use kubernetes cluster DNS to minimize unnecessary network hops. In cases where
both access is required from within and without the kubernetes cluster, multiple `openIDAllowedTokenIssuers` should
be configured, even though they will represent the _same_ token issuer backend.

### Using AuthenticationProviderToken
In order to simplify deployment and integration with this new broker plugin, there is a configuration option to use the
`AuthenticationProviderToken` plugin in conjunction with the OpenID Connect plugin.

If the `openIDAttemptAuthenticationProviderToken` is set to true, and the JWT does not have an `iss` claim, the plugin
will attempt to validate the token using the `AuthenticationProviderToken` plugin. Otherwise,
it will then attempt to retrieve a Public Key via the OpenID Connect protocol and will use that key to
validate the token. This feature is helpful because there are several pulsar components that need access to a super user
token in order to work, and deploying those components using OpenID Connect (or OAuth2.0) clients is not yet available.

### Deployment
The [Luna Streaming Helm Chart](https://github.com/datastax/pulsar-helm-chart) includes this plugin by default.

If you're looking to use this plugin without using the Luna Streaming Pulsar distribution, you will need to do the
following:

1. Include the jar for this plugin on the broker's classpath. Note that the jar produced for this plugin is an uber jar
   containing the necessary dependencies to run on a pulsar broker.
1. Configure the broker to use `com.datastax.oss.pulsar.auth.AuthenticationProviderOpenID` as the authentication
   provider class. Make sure to enable authentication on the broker.
1. Configure pulsar clients to use the `AuthenticationToken` client `Authentication` class. This is the class
   distributed as part of pulsar.

### Warning About AuthenticationProviderToken

This plugin will not work simultaneously with `org.apache.pulsar.broker.authentication.AuthenticationProviderToken`
because Pulsar Brokers load and store authentication providers by the `AuthMethodName`, and both this plugin and the 
`AuthenticationProviderToken` plugin use `token` as the `AuthMethodName`. This design decision is intentional to make
it easier to use this plugin. See [Using AuthenticationProviderToken](#Using-AuthenticationProviderToken) for details
on using both plugins together.