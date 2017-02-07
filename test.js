var TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9.ETgkTn8BaxIX4YqvUWVFPmum3moNZ7oARZtSBXb_vP4';

var koa     = require('koa');
var request = require('supertest');
var assert  = require('assert');

var koaeula  = require('./index');

describe('failure tests', function () {

  it('should throw 403 if no eula header', function(done) {
    var app = koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .expect(403)
      .end(done);
  });

  it('should return 403 if eula header is malformed', function(done) {
    var app = koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .set('Eula', 'wrong')
      .expect(403)
      .expect('Bad Eula header format. Format is "Eula: Bearer <token>"\n')
      .end(done);
  });

  it('should return 403 if eula header does not start with "Bearer "', function(done) {
    var app = koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Beer sometoken')
      .expect(403)
      .expect('Bad Eula header format. Format is "Eula: Bearer <token>"\n')
      .end(done);
  });

  it('should allow provided getToken function to throw', function(done) {
    var app = koa();

    app.use(koaeula({ secret: 'shhhh', getToken: function() {
      this.throw(403, 'Bad Eula\n');
    } }));
    request(app.listen())
      .get('/')
      .expect(403)
      .expect('Bad Eula\n')
      .end(done);
  });

  it('should throw if getToken function returns invalid jwt', function(done) {
    var app = koa();

    app.use(koaeula({ secret: 'shhhhhh', getToken: function() {
      var secret = 'bad';
      return koaeula.sign({foo: 'bar'}, secret);
    } }));
    request(app.listen())
      .get('/')
      .expect(403)
      .expect('Invalid eula token\n')
      .end(done);
  });

  it('should throw if eula header is not well-formatted jwt', function(done) {
    var app = koa();

    app.use(koaeula({ secret: 'shhhh' }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer wrongjwt')
      .expect(403)
      .expect('Invalid eula token\n')
      .end(done);
  });

  it('should throw if eula header is not valid jwt', function(done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: 'different-shhhh', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - invalid signature\n')
      .end(done);
      //   assert.equal(err.message, 'invalid signature');
  });

  it('should throw if opts.cookies is set and the specified cookie is not well-formatted jwt', function(done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret, cookie: 'jwt' }));
    app.use(function* (next) {
      this.body = this.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Cookie', 'jwt=bad' + token + ';')
      .expect(403)
      .expect('Invalid eula token\n')
      .end(done);

  });

  it('should throw if audience is not expected', function(done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar', aud: 'expected-audience'}, secret);

    var app = koa();

    app.use(koaeula({ secret: 'shhhhhh', audience: 'not-expected-audience', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - jwt audience invalid. expected: not-expected-audience\n')
      .end(done);
  });

  it('should throw if token is expired', function(done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar', exp: 1382412921 }, secret);

    var app = koa();

    app.use(koaeula({ secret: 'shhhhhh', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - jwt expired\n')
      .end(done);
  });

  it('should throw if token issuer is wrong', function(done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar', iss: 'http://foo' }, secret);

    var app = koa();

    app.use(koaeula({ secret: 'shhhhhh', issuer: 'http://wrong', debug: true }));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(403)
      .expect('Invalid eula token - jwt issuer invalid. expected: http://wrong\n')
      .end(done);
  });

  it('should throw if secret neither provide by options and middleware', function (done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar', iss: 'http://foo' }, secret);

    var app = koa();

    app.use(koaeula({debug: true}));
    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(500)
      .expect('Internal Server Error')
      .end(done);
  });

  it('should throw if secret both provide by options(right secret) and middleware(wrong secret)', function (done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar', iss: 'http://foo' }, secret);

    var app = koa();

    app.use(koaeula({secret: 'wrong secret', debug: true}));
    request(app.listen())
        .get('/')
        .set('Eula', 'Bearer ' + token)
        .expect(403)
        .expect('Invalid eula token - invalid signature\n')
        .end(done);
  });

});

describe('passthrough tests', function () {
  it('should continue if `passthrough` is true', function(done) {
    var app = koa();

    app.use(koaeula({ secret: 'shhhhhh', passthrough: true, debug: true }));
    app.use(function* (next) {
      this.body = this.state.eula;
    });

    request(app.listen())
      .get('/')
      .expect(204) // No content
      .expect('')
      .end(done);
  });
});


describe('success tests', function () {

  it('should work if eula header is valid jwt', function(done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Wrong user";
    }

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret }));
    app.use(function* (next) {
      this.body = this.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });

  it('should work if the provided getToken function returns a valid jwt', function(done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Wrong user";
    }

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();
    app.use(koaeula({ secret: secret, getToken: function() {
      return this.request.query.token;
    }}));
    app.use(function* (next) {
      this.body = this.state.eula;
    });

    request(app.listen())
      .get('/?token=' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should use the first resolved token', function(done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Wrong user";
    }

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var invalidToken = koaeula.sign({foo: 'bar'}, 'badSecret');

    var app = koa();
    app.use(koaeula({ secret: secret, cookie: 'jwt'}));
    app.use(function* (next) {
      this.body = this.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Cookie', 'jwt=' + token + ';')
      .set('Eula', 'Bearer ' + invalidToken)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should work if opts.cookies is set and the specified cookie contains valid jwt', function(done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Wrong user";
    }

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret, cookie: 'jwt' }));
    app.use(function* (next) {
      this.body = this.state.eula;
    });

    request(app.listen())
      .get('/')
      .set('Cookie', 'jwt=' + token + ';')
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });

  it('should use provided key for decoded data', function(done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Key param not used properly";
    }

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret, key: 'jwtdata' }));
    app.use(function* (next) {
      this.body = this.state.jwtdata;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });

  it('should work if secret is provided by middleware', function (done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Wrong user";
    };

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(function *(next) {
        this.state.secret = secret;
        yield next;
    });
    app.use(koaeula());
    app.use(function* (next) {
      this.body = this.state.eula;
    });

    request(app.listen())
        .get('/')
        .set('Eula', 'Bearer ' + token)
        .expect(200)
        .expect(validEulaResponse)
        .end(done);
  });


  it('should provide the raw token to the state context', function (done) {
    var validEulaResponse = function (res) {
      if (!(res.body.token === token)) return "Token not passed through";
    }

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret, key: 'jwtdata', tokenKey: 'testTokenKey' }));
    app.use(function* (next) {
      this.body = { token: this.state.testTokenKey };
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should use middleware secret if both middleware and options provided', function (done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Wrong user";
    };

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(function *(next) {
      this.state.secret = secret;
      yield next;
    });
    app.use(koaeula({secret: 'wrong secret'}));
    app.use(function* (next) {
      this.body = this.state.eula;
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

  it('should pass if the route is excluded', function(done) {
    var validEulaResponse = function(res) {
      if (!(res.body.success === true)) return "koa-eula is getting fired.";
    };

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret }).unless({ path: ['/public']}));
    app.use(function* (next) {
      this.body = { success: true };
    });

    request(app.listen())
      .get('/public')
      .set('Eula', 'wrong')
      .expect(200)
      .expect(validEulaResponse)
      .end(done);
  });

  it('should fail if the route is not excluded', function(done) {
    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret }).unless({ path: ['/public']}));
    app.use(function* (next) {
      this.body = { success: true };
    });

    request(app.listen())
      .get('/private')
      .set('Eula', 'wrong')
      .expect(403)
      .expect('Bad Eula header format. Format is "Eula: Bearer <token>"\n')
      .end(done);
  });

  it('should pass if the route is not excluded and the token is present', function(done) {
    var validEulaResponse = function(res) {
      if (!(res.body.foo === 'bar')) return "Key param not used properly";
    };

    var secret = 'shhhhhh';
    var token = koaeula.sign({foo: 'bar'}, secret);

    var app = koa();

    app.use(koaeula({ secret: secret, key: 'jwtdata' }).unless({ path: ['/public']}));
    app.use(function* (next) {
      this.body = this.state.jwtdata;
    });

    request(app.listen())
      .get('/')
      .set('Eula', 'Bearer ' + token)
      .expect(200)
      .expect(validEulaResponse)
      .end(done);

  });
});
