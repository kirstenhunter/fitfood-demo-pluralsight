var Hapi = require('hapi'),
    Wreck = require('wreck'),
    path = require('path'),
    JWT = require('jwt-simple'),
    crypto = require('crypto');

// Create a server with a host and port
var server = new Hapi.Server({ debug: { request: ['error'] } });
server.connection({ 
    host: '0.0.0.0', 
    port: parseInt(process.env.PORT, 10)
});

// Connect to database
var Datastore = require('nedb');
var db = new Datastore({
    filename: path.join(process.env.CLOUD_DIR, 'nedb.json'),
    autoload: true
});

// Bell is a third-party authentication plugin for hapi.
// Register Fitbit as an OAuth 2.0 authentication provider:
server.register(require('bell'), function(err) {
    server.auth.strategy('fitbit', 'bell', {
        provider: {
            protocol: 'oauth2',
            useParamsAuth: false,
            auth: 'https://www.fitbit.com/oauth2/authorize',
            token: 'https://api.fitbit.com/oauth2/token',
            scope: ['profile', 'activity', 'heartrate', 'location'],
            profile: function(credentials, params, get, callback) {
                get('https://api.fitbit.com/1/user/-/profile.json', null, function(profile) {
                    credentials.profile = {
                        id: profile.user.encodedId,
                        displayName: profile.user.displayName,
                        name: profile.user.fullName
                    };

                    return callback();
                });
            }
        },
        password: process.env.COOKIE_PASSWORD,
        clientId: process.env.FITBIT_OAUTH2_CLIENT_ID,
        clientSecret: process.env.FITBIT_OAUTH2_CLIENT_SECRET,
        cookie: 'bell-fitbit',
        isSecure: false // Remove if server is HTTPS, which it should be if using beyond a demo.
    });
});

// Page to start the OAuth 2.0 Authorization Code Grant Flow
server.route({
    method: 'GET',
    path:'/',
    handler: function (request, reply) {
        return reply('Go <a href="./signin">here</a> to sign in.');
    }
});

server.route({
    method: 'GET',
    path:'/signin',
    config: {
        auth: 'fitbit',
        handler: function (request, reply) {
            if (!request.auth.isAuthenticated) {
                return reply('Authentication failed due to: ' + request.auth.error.message);
            }
            
            // Set the key for this database record to the user's id
            request.auth.credentials._id = request.auth.credentials.profile.id;
            console.log(request.auth.credentials.profile.id);
            
            // Save the credentials to database
            db.update(
                {_id: request.auth.credentials.profile.id}, // query
                request.auth.credentials, // update
                {upsert: true}, // options
                function(err, numReplaced, newDoc) {
                    if (err) {
                        return reply(err).code(500);
                    }
                    console.log(request.auth.credentials.profile.id);
		            // Subscribe to Activity Data
                    Wreck.post('https://api.fitbit.com/1/user/-/activities/apiSubscriptions/' + request.auth.credentials.profile.id + '.json',
                        {
                            headers: {
                                Authorization: 'Bearer ' + request.auth.credentials.token
                            },
                            json: true
                        },
                        function(err, response, payload) {
			                if (err) {

                                return reply(err).code(500);
                            }

                            // Finally respond to the request
                            return reply('Signed in as ' + request.auth.credentials.profile.displayName);
                        }
                    );
                }
            );
        }
    }
});

// Callback page at the end of the authorization flow
server.route({
    method: 'GET',
    path:'/auth-callback',
    handler: function(request, reply) {
        return reply('Signed in as ' + request.auth.credentials.profile.displayName);
    }
});

// Add the route to receive and process webhook requests
server.route({
    method: 'POST',
    path:'/webhook-receiver',
    config: {
        payload: {
            output: 'data',
            parse: false
        }
    },
    handler: function (request, reply) {
        reply().code(204);
        console.log("I'm in the handler, yo!");
        console.log(JSON.parse(request.payload.toString())[0]);
        // Get Activities and Food and heartrate
        // If steps < 10000/hours and different from last send activity summary
        // If protein < 80/hours and different from last send protein
        // If send either, send heartrate average
        console.log("That was a test.");
        //console.log(request.payload.toString());

        
        // Process this request after the response is sent
        var answer = JSON.parse(request.payload.toString());
        console.log("Answer:" + answer);
        processWebhookNotification(answer);
    }
});

function processWebhookNotification(notifications) {
    // Multiple notifications may be received in a request
    // TODO: Handle more than one notification
    console.log("Notifications:" + notifications);
    console.log("Gotcha");
    // Lookup the auth credentials of the user
    getAccessTokenByUserId(
        notifications[0].ownerId,
        function(err, authCredentials) {
            console.log('Doing something with the credentials...', authCredentials);
            
            Wreck.get('https://api.fitbit.com/1/user/-/profile.json',
                {
                    headers: {
                        Authorization: 'Bearer ' + authCredentials.token
                    },
                    json: true
                },
                function(err, response, payload) {
                    if (err) {
                        throw new Error(err);
                    }

                    console.log('Profile fetched: ', payload);
                }
            );
        }
    );
}

// Fitbit Web API OAuth 2.0 access tokens expire frequently and must be refreshed
function getAccessTokenByUserId(userId, cb) {
    db.findOne({_id: userId}, function(err, doc) {
        if (err) {
            throw new Error(err);
        }

        // Check to see if the token has expired
        var decodedToken = JWT.decode(doc.token, null, true);

        if (Date.now()/1000 > decodedToken.exp) {
            // Token expired, so refresh it.
            Wreck.post('https://api.fitbit.com/oauth2/token',
                {
                    headers: {
                        Authorization: 'Basic ' + new Buffer(process.env.FITBIT_OAUTH2_CLIENT_ID + ':' + process.env.FITBIT_OAUTH2_CLIENT_SECRET).toString('base64'),
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    json: true,
                    payload: 'grant_type=refresh_token&refresh_token=' + doc.refreshToken
                },
                function(err, response, payload) {
                    if (err) {
                        throw new Error(err);
                    }

                    // Save the new token
                    doc.token = payload.access_token;
                    doc.refreshToken = payload.refresh_token;

                    db.update(
                        {_id: doc._id}, // query
                        doc, // update
                        {}, // options
                        function(err, numReplaced, newDoc) {
                            if (err) {
                                throw new Error(err);
                            }

                            return cb(null, doc);
                        }
                    );
                }
            );
        } else {
            return cb(null, doc);
        }
    });
}

// Start the server
server.start(function () {
    console.log('Server running at:', server.info.uri);
});
