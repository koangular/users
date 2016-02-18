import jwt from 'jwt-simple';
import moment from 'moment';

import config from 'config';

const log = config.get('log');
const tokenSecret = config.get('auth.tokenSecret');

export function encodeUser(user) {
    return jwt.encode({
            sub: user._id,
            role: user.role
        },
        tokenSecret);
}

export function decodeUser(token) {
    var payload = jwt.decode(token, tokenSecret);

    return {
        _id: payload.sub,
        role: payload.role
    };
}
export function encodeAuth(auth) {
    return jwt.encode({
            auth,
            exp: moment().add(1, 'hours').unix()
        },
        tokenSecret);
}

export function decodeAuth(token) {
    const payload = jwt.decode(token, tokenSecret);
    if (payload.exp < moment().unix()) {
        throw Error('Token expired');
    }
    return payload.auth;
}