import {decodeUser, decodeAuth} from './tokens';

export async function ensureAuth(ctx, next) {
    if (!ctx.headers.hasOwnProperty('x-auth-token')) {
        ctx.throw(401);
    }

    try {
        ctx.state.auth = decodeAuth(ctx.headers['x-auth-token']);
    } catch (e) {
        ctx.throw(401);
    }

    await next();
}

export async function ensureUser(ctx, next) {
    if (!ctx.headers.hasOwnProperty('x-access-token')) {
        ctx.throw(401);
    }

    try {
        ctx.state.user = decodeUser(ctx.headers['x-access-token']);

        if (ctx.state.user.role === 'admin' &&  ctx.headers.hasOwnProperty('x-access-override')) {
            ctx.state.user = JSON.parse(ctx.headers['x-access-override']);
        }
    } catch (e) {
        ctx.throw(401);
    }

    await next();
}

export function ensureRole(role) {
    return async function(ctx, next) {
        await ensureUser(ctx, async function() {
            if (ctx.state.user.role !== role) {
                ctx.throw(403);
            } else {
                await next();
            }
        });
    }
}

export const ensureAdmin = ensureRole('admin');