const express = require('express');
const session = require('express-session');
const { Issuer } = require('openid-client');

const app = express();

const port = 4000


// Configure express-session middleware
app.use(session({
    secret: 'some-secret',
    resave: false,
    saveUninitialized: true,
}));

// Retrieve OpenID Connect configuration from the issuer's discovery document
Issuer.discover('...')
    .then((issuer) => {
        // Initialize the client with the client ID and secret
        const client = new issuer.Client({
            // ... ,
            noCache: true
        });

        // Create a route for initiating the login flow
        app.get('/login', (req, res, next) => {
            // ...
        });

        // Create a route for handling the callback from the authorization server
        app.get("/login/redirect", async (req, res, next) => {
            const params = client.callbackParams(req);
            // get the params https://github.com/panva/node-openid-client/blob/main/docs/README.md#clientcallbackparamsinput
            // exchange the authorization code (in the params_) for an actual tokenset, log it to your screen.
            // ...
        });

        // Create a route for displaying the user profile
        app.get('/profile', async (req, res, next) => {
            // ... display some personal content as a json
        });

        app.get('/logout', (req, res) => {
            // ...
        });

        // Start the server
        app.listen(port, () => {
            console.log('Server listening on ' + port);
        });
    })
    .catch((err) => {
        console.error(err);
    });