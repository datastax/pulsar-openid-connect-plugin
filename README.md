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
| openIDAcceptedTimeLeewaySeconds | `0` | Number (no decimals) | The number of seconds that a token will be accepted past its expiration time. |
| openIDJwkCacheSize | `10` | Number (no decimals) | The number of JWK values to keep in the cache. |
| openIDJwkExpiresMinutes | `5` | Number (no decimals) | The length of time to store a JWK before calling the issuer again. Note that this time is also the maximum time that a revoked token can be used. A longer window may improve performance, but it also increases the length of time than a deactivated token could be used. |
| openIDAttemptAuthenticationProviderTokenFirst | `true` | Boolean | Whether to also use the `AuthenticationProviderToken` class when attempting verification of the JWT. See [Using AuthenticationProviderToken](#Using-AuthenticationProviderToken). | 

Note that the only required configuration is the `openIDAllowedTokenIssuers`.

### Supported Algorithms
Here is a list of supported algorithms for the OpenID Connect auth plugin: RS256, RS384, RS512, ES256, ES384, ES512.
The algorithm names follow the spec in [RFC-7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1).

### Keycloak

### Issuers
The `openIDAllowedTokenIssuers` configuration is essential when configuring which token issuers can be trusted. It is
recommended by [RFC-7515](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2) that trusted URIs should include
transport security to ensure the authenticity of the Public Keys retrieved from the issuers. This plugin does not
enforce this requirement. If a configured issuer begins with `http`, the plugin will not modify the issuer's URI. If the
configured issuer does not begin with `http`, the plugin will prepend `https://` to the issuer's domain. (Note that
this design decision has not been finalized and is subject to change.)

Note, also, that the issuers claim is checked by a direct string equality check, per [RFC-7519](https://datatracker.ietf.org/doc/html/rfc7519#section-7.3). As such, it is necessary
to make sure that the `iss` claim on your JWT is contained in this collection. If the plugin prepends `https://`, that
will not be included in the equality check. (This behavior may change.)

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
In order to simplify deployment and integration with this new broker plugin, there is a configuration option that allows
users to configure the `AuthenticationProviderToken` as the first attempt when 

The current implementation is naive. If the `openIDAttemptAuthenticationProviderTokenFirst` is configured to true, the
plugin will first attempt to validate the token using the `AuthenticationProviderToken` plugin. If that fails,
it will then attempt to retrieve a Public Key via the OpenID Connect protocol and will use that key to
validate the token. This feature is helpful because there are several pulsar components that need access to a super user
token in order to work.

In the future, it might be better to include a special claim on the JWT to indicate which provider should be used
to validate the token.

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