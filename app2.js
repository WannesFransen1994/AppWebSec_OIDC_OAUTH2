const express = require('express');
const session = require('express-session');
const { Issuer } = require('openid-client');

const app = express();

const port = 4001
const secrets = {
    client_id: 'app2',
    client_secret: '4Vbl9LgdIG6iJdmw8xCJXrYUxzjDcZ1V',
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

        app.get('/request-extra-scope', async (req, res, next) => {
            try {
                if (!req.session.tokenSet) {
                    res.redirect('/login');
                    return;
                }

                // Check if the user has the required scope for Service A
                console.log(req.session.tokenSet)
                const hasServiceAScope = req.session.tokenSet.scope.split(' ').includes('app1-client-scope');

                if (hasServiceAScope) {
                    // User has the required scope for Service A, display the profile
                    const user = await client.userinfo(req.session.tokenSet.access_token);
                    console.log("has already service access")
                    console.log(JSON.stringify(req.session.tokenSet))
                    res.send(user);
                } else {
                    // User does not have the required scope for Service A, request the new scope
                    const params = {
                        redirect_uri: redirect_uri,
                        scope: ['openid profile app1-client-scope'], // Add the new scope
                        prompt: 'consent' // Force the user to grant permission for the new scope
                    };
                    const authorizationUrl = client.authorizationUrl(params);
                    res.redirect(authorizationUrl);
                }
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