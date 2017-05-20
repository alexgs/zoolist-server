'use strict';

// TODO 1. Setup SSL on EC2 and Nginx.
// TODO 2. Get the authentication flow working on EC2.

const cookieParser = require( 'cookie-parser' ),
    config = require( './config/config.json' ),
    express = require( 'express' ),
    OAuth = require( 'oauth' ).OAuth,
    url = require( 'url' )
;

const app = express();
const oauth = new OAuth(
    config.requestTokenUrl,
    config.accessTokenUrl,
    config.consumerKey,
    config.consumerSecret,
    config.oauthVersion,
    config.oauthCallback,
    config.oauthSignature
);

app.use( cookieParser() );

app.get( '/authenticate', ( req, res ) => {
    oauth.getOAuthRequestToken( ( error, oauth_token, oauth_token_secret, results ) => {
        if ( error ) {
            console.log( error );
            res.send( 'Authentication failed!' );
        } else {
            res.cookie( 'oauth_token', oauth_token, { httpOnly: true } );
            res.cookie( 'oauth_token_secret', oauth_token_secret, { httpOnly: true } );
            res.redirect( 'https://twitter.com/oauth/authorize' + '?oauth_token=' + oauth_token );
        }
    } );
} );

app.get( url.parse( config.oauthCallback ).path, function( req, res ) {
    authenticate( req, res, function( err ) {
        if ( err ) {
            res.send( 'Error: ' + err );
        } else {
            // res.redirect( '/app' );
            res.send( 'Success!' );
        }
    } );
} );

app.get( '/', ( request, response ) => response.sendFile( __dirname + '/index.html' ) );

function authenticate( req, res, cb ) {
    if ( !( req.cookies.oauth_token && req.cookies.oauth_token_secret && req.query.oauth_verifier ) ) {
        return cb( 'Request does not have all required keys' );
    }

    // Clear the request token data from the cookies
    res.clearCookie( 'oauth_token' );
    res.clearCookie( 'oauth_token_secret' );

    // Exchange oauth_verifier for an access token
    oauth.getOAuthAccessToken(
        req.cookies.oauth_token,
        req.cookies.oauth_token_secret,
        req.query.oauth_verifier,
        function( error, oauth_access_token, oauth_access_token_secret, results ) {
            if ( error ) {
                return cb( error );
            }

            // Get the user's Twitter ID
            oauth.get( 'https://api.twitter.com/1.1/account/verify_credentials.json',
                oauth_access_token, oauth_access_token_secret,
                function( error, data ) {
                    if ( error ) {
                        console.log( error );
                        return cb( error );
                    }

                    // Parse the JSON response
                    data = JSON.parse( data );

                    // Store the access token, access token secret, and user's Twitter ID in cookies
                    res.cookie( 'access_token', oauth_access_token, { httpOnly: true } );
                    res.cookie( 'access_token_secret', oauth_access_token_secret, { httpOnly: true } );
                    res.cookie( 'twitter_id', data.id_str, { httpOnly: true } );

                    // Tell router that authentication was successful
                    cb();
                } );
        } );
}

// Start listening for requests
app.listen( config.port, () => {
    console.log( `Listening on port ${config.port}` );
} );
