[![Build Status](https://travis-ci.org/xploratics/koa-eula.svg)](https://travis-ci.org/xploratics/koa-eula)
[![dependencies Status](https://david-dm.org/xploratics/koa-eula/status.svg)](https://david-dm.org/xploratics/koa-eula)
[![devDependencies Status](https://david-dm.org/xploratics/koa-eula/dev-status.svg)](https://david-dm.org/xploratics/koa-eula?type=dev)

# koa-eula

Koa middleware that validates JSON Web Tokens and sets `ctx.state.eula`
(by default) if a valid EULA token is provided.

This module lets you validate EULA on HTTP requests using JSON Web Tokens
in your [Koa](http://koajs.com/) (node.js) applications.

## Installation

```bash
npm install koa-eula
```

## Usage

The JWT eula middleware validate EULA acceptation of callers using a JWT
token. If the token is valid, `ctx.state.eula` (by default) will be set
with the JSON object decoded to be used by later middleware.

### Retrieving the token

The token is normally provided in a HTTP header (`Eula`), but it
can also be provided in a cookie by setting the `opts.cookie` option
to the name of the cookie that contains the token. Custom token retrieval
can also be done through the `opts.getEulaToken` option. The provided function
should match the following interface:

```js
/**
 * Your custom token resolver
 * @this The ctx object passed to the middleware
 *
 * @param  {object}      opts The middleware's options
 * @return {String|null}      The resolved token or null if not found
 */
```

The resolution order for the token is the following. The first non-empty token resolved will be the one that is verified.

- `opts.getToken` function
- check the cookies (if `opts.cookie` is set)
- check the Authorization header for a bearer token

### Passing the secret

Normally you provide a single shared secret in `opts.secret`, but another
alternative is to have an earlier middleware set `ctx.state.secret`,
typically per request. If this property exists, it will be used instead
of the one in `opts.secret`.

## Example

```js
var koa = require('koa');
var eula = require('koa-eula');

var app = koa();

// Custom 403 handling if you don't want to expose koa-eula errors to users
app.use(function(ctx, next) {
  return next().catch((err) => {
    if (401 == err.status) {
      ctx.status = 401;
      ctx.body = 'Protected resource, use Eula header to get access\n';
    } else {
      throw err;
    }
  });
});

// Unprotected middleware
app.use(function(ctx, next) {
  if (ctx.url.match(/^\/public/)) {
    ctx.body = 'unprotected\n';
  } else {
    return next();
  }
});

// Middleware below this line is only reached if eula token is valid
app.use(eula({ secret: 'shared-secret' }));

// Protected middleware
app.use(function (ctx){
  if (ctx.url.match(/^\/api/)) {
    ctx.body = 'protected\n';
  }
});

app.listen(3000);
```

Alternatively you can conditionally run the `eula` middleware under certain conditions:

```js
var koa = require('koa');
var eula = require('koa-eula');

var app = koa();

// Middleware below this line is only reached if eula token is valid
// unless the URL starts with '/public'
app.use(eula({ secret: 'shared-secret' }).unless({ path: [/^\/public/] }));

// Unprotected middleware
app.use(function *(next){
  if (this.url.match(/^\/public/)) {
    this.body = 'unprotected\n';
  } else {
    yield next;
  }
});

// Protected middleware
app.use(function *(){
  if (this.url.match(/^\/api/)) {
    this.body = 'protected\n';
  }
});

app.listen(3000);
```

For more information on `unless` exceptions, check [koa-unless](https://github.com/Foxandxss/koa-unless).

You can also add the `passthrough` option to always yield next,
even if no valid Authorization header was found:

```js
app.use(eula({ secret: 'shared-secret', passthrough: true }));
```

This lets downstream middleware make decisions based on whether `ctx.state.user` is set.

If you prefer to use another ctx key for the decoded data, just pass in `key`, like so:

```js
app.use(eula({ secret: 'shared-secret', key: 'euladata' }));
```

This makes the decoded data available as `ctx.state.euladata`.

If the `tokenKey` option is present, and a valid token is found, the original raw token
is made available to subsequent middleware as `ctx.state[opts.tokenKey]`.

You can specify audience and/or issuer as well:

```js
app.use(eula({ secret:   'shared-secret',
               audience: 'http://myapi/protected',
               issuer:   'http://issuer' }));
```

If the eula has an expiration (`exp`), it will be checked.

## Tests

```bash
npm install
npm test
```

## Credits

This code is largely based on [koa-jwt](https://github.com/koa/koa-jwt).

- [Stian Grytøyr](http://stian.grytoyr.net/)

## License

[The MIT License](http://opensource.org/licenses/MIT)
