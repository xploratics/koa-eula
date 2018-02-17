const TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9.ETgkTn8BaxIX4YqvUWVFPmum3moNZ7oARZtSBXb_vP4';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const koa = require('koa');
const koaeula = require('../lib');
const request = require('supertest');

describe('failure tests', function () {

  it('should throw 403 if no eula header', function (done) {
    const app = new koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .expect(403)
      .end(done);
  });

  it('should return 403 if eula header is malformed', function (done) {
    const app = new koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .set('Eula', 'wrong')
      .expect(403)
      .expect('Bad Eula header format. Format is "Eula: Bearer <token>"\n')
      .end(done);
  });

  it('should return 403 if eula header does not start with "Bearer "', function (done) {
    const app = new koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Beer sometoken')
      .expect(403)
      .expect('Bad Eula header format. Format is "Eula: Bearer <token>"\n')
      .end(done);
  });

  it('should allow provided getToken function to throw', function (done) {
    const app = new koa();

    app.use(koaeula({
      secret: 'shhhh',
      getToken: ctx => ctx.throw(403, 'Bad Eula\n')
    }));

    request(app.listen())
      .get('/')
      .expect(403)
      .expect('Bad Eula\n')
      .end(done);
  });

  it('should throw if getToken function returns invalid jwt', function (done) {
    const app = new koa();

    app.use(koaeula({
      secret: 'shhhhhh',
      getToken: ctx => {
        var secret = 'bad';
        return jwt.sign({ foo: 'bar' }, secret);
      }
    }));
    request(app.listen())
      .get('/')
      .expect(403)
      .expect('Invalid eula token\n')
      .end(done);
  });

  it('should throw if eula header is not well-formatted jwt', function (done) {
    const app = new koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer wrongjwt')
      .expect(403)
      .expect('Invalid eula token\n')
      .end(done);
  });

  it('should throw if eula header is not valid jwt', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: 'different-shhhh', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - invalid signature\n')
      .end(done);
    //   assert.equal(err.message, 'invalid signature');
  });

  it('should throw if opts.cookies is set and the specified cookie is not well-formatted jwt', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: secret, cookie: 'jwt' }));
    app.use(async next => this.body = this.state.eula);

    request(app.listen())
      .get('/')
      .set('Cookie', 'jwt=bad' + token + ';')
      .expect(403)
      .expect('Invalid eula token\n')
      .end(done);

  });

  it('should throw if audience is not expected', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', aud: 'expected-audience' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: 'shhhhhh', audience: 'not-expected-audience', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - jwt audience invalid. expected: not-expected-audience\n')
      .end(done);
  });

  it('should throw if token is expired', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', exp: 1382412921 }, secret);
    var app = new koa();

    app.use(koaeula({ secret: 'shhhhhh', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - jwt expired\n')
      .end(done);
  });

  it('should throw if token issuer is wrong', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: 'shhhhhh', issuer: 'http://wrong', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - jwt issuer invalid. expected: http://wrong\n')
      .end(done);
  });

  it('should throw if secret neither provide by options and middleware', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret);
    const app = new koa();

    app.use(koaeula({ debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(500)
      .expect('Internal Server Error')
      .end(done);
  });

  it('should throw if secret both provide by options(right secret) and middleware(wrong secret)', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: 'wrong secret', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - invalid signature\n')
      .end(done);
  });

});

describe('passthrough tests', function () {
  it('should continue if `passthrough` is true', function (done) {
    const app = new koa();

    app.use(koaeula({ secret: 'shhhhhh', passthrough: true, debug: true }));
    app.use(ctx => {
      ctx.body = ctx.state.eula;
    });

    request(app.listen())
      .get('/')
      .expect(204) // No content
      .expect('')
      .end(done);
  });
});


describe('success tests', function () {

  it('should work if eula header is valid jwt', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar'))
        return "Wrong user";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: secret }));
    app.use(ctx => {
      ctx.body = ctx.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });

  it('should work if the provided getToken function returns a valid jwt', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar'))
        return "Wrong user";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({
      secret: secret,
      getToken: ctx => ctx.request.query.token
    }));

    app.use(ctx => {
      ctx.body = ctx.state.eula;
    });

    request(app.listen())
      .get('/?token=' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should use the first resolved token', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar'))
        return "Wrong user";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const invalidToken = jwt.sign({ foo: 'bar' }, 'badSecret');
    const app = new koa();

    app.use(koaeula({ secret: secret, cookie: 'jwt' }));
    app.use(ctx => {
      ctx.body = ctx.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Cookie', 'jwt=' + token + ';')
      .set('Eula', 'Bearer ' + invalidToken)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should work if opts.cookies is set and the specified cookie contains valid jwt', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar'))
        return "Wrong user";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: secret, cookie: 'jwt' }));
    app.use(ctx => {
      ctx.body = ctx.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Cookie', 'jwt=' + token + ';')
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });

  it('should use provided key for decoded data', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar'))
        return "Key param not used properly";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    var app = new koa();

    app.use(koaeula({ secret: secret, key: 'jwtdata' }));
    app.use(ctx => {
      ctx.body = ctx.state.jwtdata;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });

  it('should work if secret is provided by middleware', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar'))
        return "Wrong user";
    };

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use((ctx, next) => {
      ctx.state.secret = secret;
      return next();
    });

    app.use(koaeula());
    app.use(ctx => {
      ctx.body = ctx.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });


  it('should provide the raw token to the state context', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.token === token)) return "Token not passed through";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: secret, key: 'jwtdata', tokenKey: 'testTokenKey' }));
    app.use(ctx => {
      ctx.body = { token: ctx.state.testTokenKey };
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should use middleware secret if both middleware and options provided', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar')) return "Wrong user";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use((ctx, next) => {
      ctx.state.secret = secret;
      return next();
    });

    app.use(koaeula({ secret: 'wrong secret' }));
    app.use(ctx => {
      ctx.body = ctx.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });
});

describe('unless tests', function () {

  it('should pass if the route is excluded', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.success === true))
        return "koa-eula is getting fired.";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: secret }).unless({ path: ['/public'] }));
    app.use(ctx => {
      ctx.body = { success: true };
    });

    request(app.listen())
      .get('/public')
      .set('Eula', 'wrong')
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should fail if the route is not excluded', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: secret }).unless({ path: ['/public'] }));
    app.use(ctx => {
      ctx.body = { success: true };
    });

    request(app.listen())
      .get('/private')
      .set('Eula', 'wrong')
      .expect(403)
      .expect('Bad Eula header format. Format is "Eula: Bearer <token>"\n')
      .end(done);
  });

  it('should pass if the route is not excluded and the token is present', function (done) {
    function validEulaResponse(res) {
      if (!(res.body.foo === 'bar'))
        return "Key param not used properly";
    }

    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const app = new koa();

    app.use(koaeula({ secret: secret, key: 'jwtdata' }).unless({ path: ['/public'] }));
    app.use(ctx => {
      ctx.body = ctx.state.jwtdata;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });
});
