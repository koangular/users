import NodeCache from 'node-cache';
import validator from 'validator';
import crypto from 'crypto';
import base58 from 'bs58';
import request from 'request';
import b64url from 'base64-url';
import Bluebird from 'bluebird';
import SparkPost from 'sparkpost';

import Router from 'koa-router';
import config from 'config'
import koangular from "@amitport/koangular";

import {encodeUser, encodeAuth} from '../tokens';
import {ensureAuth} from '../../middlewares';

import views from '../views'
import bodyParser from '../bodyParser';
import User from '../models/user';

const sparkPost = new SparkPost();

// use in-memory cache for random tokens (TODO move to DB when moving to cluster)
// keep email tokens for an hour check every 10 minutes for deleting expired tokens
const emailTokenCache = new NodeCache({stdTTL: 3600, checkperiod: 600});

const auth = Router();

const post = Bluebird.promisify(request.post);

auth.get('/api/auth/google', async (ctx) => {
    // Exchange authorization code for access token.
    const googleTokensResponse = (await post({
        url: 'https://www.googleapis.com/oauth2/v4/token',
        form: {
            code: ctx.query.code,
            client_id: '162817514604-3flbnsg9cali5j0mrnqjmgi2h6keo7uk.apps.googleusercontent.com',
            client_secret: config.get('auth.googleSecret'),
            redirect_uri: `${process.env.HOST_URL}/api/auth/google`,
            grant_type: 'authorization_code'
        },
        json: true
    }));
    if (googleTokensResponse.statusCode != 200) {
        console.log('unexpected return status from google ' + googleTokensResponse.status);
        console.log(googleTokensResponse.body);
        ctx.throw(500);
    }

    const googleTokens = googleTokensResponse.body;
    // decode the id (no need to verify since we just got this directly from google via https)
    const decodedIdToken = JSON.parse(b64url.decode(googleTokens.id_token.split('.', 2)[1]));

    const user = await User.findOne({google: decodedIdToken.sub}).select('role').lean().exec();

    const tokens = (user != null) ? {
        access: encodeUser(user)
    } : {
        auth: encodeAuth({method: 'google', google: decodedIdToken.sub})
    }

    ctx.body = await views('provider-popup-redirect.html.ejs', {
            __flash: JSON.stringify({tokens})
        }
    );
    ctx.type = 'text/html';
});

auth.post('/api/auth/signInWithEmail', bodyParser, async (ctx) => {
    const {email, path} = ctx.request.body;
    if (!validator.isIn(path, ['/', '/users/me']) // hard-code white-list redirect paths
        || !validator.isEmail(email)) {
        ctx.throw(400);
    }

    const emailToken = base58.encode(crypto.randomBytes(16));
    if (!emailTokenCache.set(emailToken, {email: validator.normalizeEmail(email), path})) {
        ctx.throw(500);
    }

    const cbUrl = `${process.env.HOST_URL}/et/${emailToken}`;
    sparkPost.transmissions.send({
        transmissionBody: {
            content: {
                from: {
                    name: "cutlog",
                    email: "sandbox@sparkpostbox.com"
                },
                subject: 'e-mail sign-in',
                reply_to: 'Amit Portnoy <amit.portnoy@gmail.com>',
                text: `
Sign-in to cutlog with the following link:

${cbUrl}
`,
                html: `
<div>Sign-in to cutlog with the following link:
<br><br>
<a href="${cbUrl}">${cbUrl}</a>
</div>
`
            },
            recipients: [{address: {email}}]
        }
    }, function (err, res) {
        if (err) {
            console.log('Whoops! Something went wrong');
            console.error(err);
        } else {
            console.log(res.body);
        }
    });

    // next if anyone calls /et/<emailToken> before exp it will be redirected to path
    console.log('passwordless sent: ' + emailToken);
    ctx.status = 202; //(Accepted)
});

auth.get('/et/:et', async (ctx) => {
    const emailToken = ctx.params.et;
    console.log('passwordless got: ' + emailToken);
    const storedValue = emailTokenCache.get(emailToken);
    let passwordless;
    if (storedValue == null) {
        ctx.throw(401);
    }

    emailTokenCache.del(emailToken);


    const user = await User.findOne({email: storedValue.email}).select('role').lean().exec();

    const tokens = (user != null) ? {
        access: encodeUser(user)
    } : {
        auth: encodeAuth({method: 'email', email: storedValue.email})
    };

    ctx.body = await koangular.views('index.html.ejs', {
            __flash: JSON.stringify({tokens, originalPath: storedValue.path}),
            env: process.env.NODE_ENV
        }
    );
    ctx.type = 'text/html';
});

auth.post('/api/auth/register', ensureAuth, bodyParser, async (ctx) => {
    const user = new User();
    user.username = ctx.request.body.username;
    const auth = ctx.state.auth;
    user[auth.method] = ctx.state.auth[auth.method];

    try {
        ctx.body = {access: encodeUser(await user.trySave())};
    } catch(err) {
        if (err.name === 'ValidationError'
            &&
            err.errors.hasOwnProperty('username')
            &&
            err.errors.username.kind === 'Duplicate value') {
            ctx.throw(409);
        }
        throw err;
    }
});

export default auth;