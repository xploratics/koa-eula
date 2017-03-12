'use strict';

const unless = require('koa-unless');
const verify = require('./verify');

const resolveEulaHeader = require('./resolvers/eula-header');
const resolveCookies = require('./resolvers/cookie');

module.exports = (opts = {}) => {
  const { debug, getToken, isRevoked, key = 'eula', passthrough, tokenKey = 'eula-token' } = opts;
  const tokenResolvers = [resolveCookies, resolveEulaHeader];

  if (getToken && typeof getToken === 'function') {
    tokenResolvers.unshift(getToken);
  }

  const middleware = async function jwt(ctx, next) {
    let token;
    tokenResolvers.find(resolver => token = resolver(ctx, opts));

    if (!token && !passthrough) {
      ctx.throw(403, 'No eula token found\n');
    }

    const { state: { secret = opts.secret } = {} } = ctx;
    if (!secret) {
      ctx.throw(500, 'Invalid eula secret\n');
    }

    try {
      const decodedToken = await verify(token, secret, opts);

      if (isRevoked) {
        const tokenRevoked = await isRevoked(ctx, decodedToken, token);
        if (tokenRevoked) {
          throw new Error('Revoked eula token');
        }
      }

      ctx.state = ctx.state || {};
      ctx.state[key] = decodedToken;
      if (tokenKey) {
        ctx.state[tokenKey] = token;
      }

    } catch (e) {
      if (!passthrough) {
        const debugString = debug ? ` - ${e.message}` : '';
        const msg = `Invalid eula token${debugString}\n`;
        ctx.throw(403, msg);
      }
    }

    return next();
  };

  middleware.unless = unless;
  return middleware;
};
