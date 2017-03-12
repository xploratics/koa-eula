/**
 * resolveEulaHeader - Attempts to parse the token from the eula header
 *
 * This function checks the eula header for a `Bearer <token>` pattern and return the token section
 *
 * @param {Object}        ctx  The ctx object passed to the middleware
 * @param {Object}        opts The middleware's options
 * @return {String|null}  The resolved eula token or null if not found
 */
module.exports = function resolveEulaHeader(ctx, opts) {
  if (!ctx.header || !ctx.header.eula) {
    return;
  }

  const parts = ctx.header.eula.split(' ');

  if (parts.length === 2) {
    const scheme = parts[0];
    const credentials = parts[1];

    if (/^Bearer$/i.test(scheme)) {
      return credentials;
    }
  }
  if (!opts.passthrough) {
    ctx.throw(403, 'Bad Eula header format. Format is "Eula: Bearer <token>"\n');
  }
};
