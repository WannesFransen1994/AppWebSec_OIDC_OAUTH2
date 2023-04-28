const express = require('express');
const session = require('express-session');
const { Issuer } = require('openid-client');
const { jwtVerify } = require('jose');

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();

const port = 4000
const secrets = {
    client_id: 'app1',
    client_secret: 'feRTNnqFpCUjuGMJlbBtMBAiEnvt0jaU',
    redirect_path: "/login/redirect",
    keycloak_host: "http://localhost:8080",
    realm_name: "my-demo-realm"
}

const redirect_uri = "http://localhost:" + port + secrets.redirect_path
const keycloak_realm_uri = secrets.keycloak_host + "/realms/" + secrets.realm_name


// Configure express-session middleware
app.use(session({
    secret: 'some-secret',
    resave: false,
    saveUninitialized: true,
}));

// Retrieve OpenID Connect configuration from the issuer's discovery document
Issuer.discover(keycloak_realm_uri)
    .then((issuer) => {
        // Initialize the client with the client ID and secret
        const client = new issuer.Client({
            client_id: secrets.client_id,
            client_secret: secrets.client_secret,
            redirect_uris: [redirect_uri],
            response_types: ['code'],
            noCache: true
        });

        // Create a route for initiating the login flow
        app.get('/login', (req, res, next) => {
            const params = {
                redirect_uri: redirect_uri,
                scope: 'openid profile',
                prompt: 'login', // Set the prompt parameter to 'login'
            };
            const authorizationUrl = client.authorizationUrl(params);
            res.redirect(authorizationUrl);
        });

        // Create a route for handling the callback from the authorization server
        app.get(secrets.redirect_path, async (req, res, next) => {
            try {
                const params = client.callbackParams(req);
                const tokenSet = await client.callback(redirect_uri, params);
                console.log(tokenSet)
                req.session.tokenSet = tokenSet;
                res.redirect('/profile');
            } catch (err) {
                next(err);
            }
        });

        // Create a route for displaying the user profile
        app.get('/profile', async (req, res, next) => {
            try {
                if (!req.session.tokenSet) {
                    res.redirect('/login');
                    return;
                }
                const user = await client.userinfo(req.session.tokenSet.access_token);
                res.send(user);
            } catch (err) {
                next(err);
            }
        });

        app.get('/protected/resource', async (req, res, next) => {
            try {
                // const tokenSet = req.session.tokenSet;
                const tokenSet = JSON.parse(req.headers.authorization);

                if (!tokenSet) {
                    res.sendStatus(401);
                    return;
                }

                // Verify that the access token includes the 'service-a-scope' scope
                const scopes = tokenSet.scope.split(' ');
                if (!scopes.includes('app1-client-scope')) {
                    res.sendStatus(403);
                    return;
                }



                const client = jwksClient({ jwksUri: issuer.jwks_uri });
                console.log(issuer.jwks_uri)
                function getKey(header, callback) {
                    client.getSigningKey(header.kid, function (err, key) {
                        console.log(key)
                        console.log(key.getPublicKey())
                        const signingKey = key.getPublicKey() || key.rsaPublicKey;
                        callback(null, signingKey);
                    });
                }

                const token = tokenSet.access_token;
                jwt.verify(token, getKey, { algorithms: ['RS256'] }, function (err, decoded) {
                    if (err) {
                        console.error(err);
                        return;
                    }

                    // If expired, returns error. Assuming that no error = good
                    res.send('Protected Resource');
                });

                // // Verify the token signature using the JWKS from the issuer
                // // const jwks = await issuer.keystore();
                // console.log(issuer.jwks_uri)
                // console.log(tokenSet.access_token)
                // const jwksUri = issuer.jwks_uri
                // // Fetch the JWKS from the issuer
                // const response = await fetch(jwksUri);
                // const jwks = await response.json();
                // console.log(jwks)

                // // Verify the token signature using the JWKS
                // const verified = jwtVerify(tokenSet.access_token, jwks);

                // // If the token is valid, return the protected resource
                // if (verified) {
                //     res.send('Protected Resource');
                // } else {
                //     res.sendStatus(401);
                // }
            } catch (err) {
                next(err);
            }
        });

        app.get('/logout', (req, res) => {
            const tokenSet = req.session.tokenSet;

            if (tokenSet) {
                // Revoke the access token
                client.revoke(tokenSet.access_token);

                // Clear the session and redirect to the login page
                req.session.destroy(() => {
                    res.redirect('/login');
                });
            } else {
                res.redirect('/login');
            }
        });

        // Start the server
        app.listen(port, () => {
            console.log('Server listening on ' + port);
        });
    })
    .catch((err) => {
        console.error(err);
    });