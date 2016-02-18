import Router from 'koa-router';
import {ensureUser, ensureAdmin} from '../middlewares';
import User from '../models/user';

const users = Router();

users.get('/api/users/me', ensureUser, async (ctx) => {
    const user = await User.findById(ctx.state.user._id, '-_id username role avatarImageUrl', {lean: true}).exec();
    if (user == null) {
        ctx.throw(404);
    }
    ctx.body = user;
});

users.get('/api/users', ensureAdmin, async (ctx) => {
    ctx.body = await User.find({}, 'username role avatarImageUrl', {lean: true}).exec();
});

export default users;