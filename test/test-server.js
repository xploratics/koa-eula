var koa = require('koa');
var koaeula = require('../lib');

var profile = {
  id: 123
};

var token = koaeula.sign(profile, 'secret', { expiresInMinutes: 60*5 });

console.log('Starting koa-jwt test server on http://localhost:3000/');
console.log('');
console.log('You can test the server by issuing curl commands like the following:');
console.log('')
console.log('  curl http://localhost:3000/public/foo            # should succeed (return "unprotected")');
console.log('  curl http://localhost:3000/api/foo               # should fail (return "403 Unauthorized ...")');
console.log('  curl -H "Authorization: Bearer ' + token + '" http://localhost:3000/api/foo   # should succeed (return "protected")');
console.log('')

var app = koa();

// Custom 403 handling
app.use(function *(next){
  try {
    yield next;
  } catch (err) {
    if (403 == err.status) {
      this.status = 403;
      this.body = '403 Unauthorized - Protected resource, use Eula header to get access\n';
    } else {
      throw err;
    }
  }
});

// Unprotected middleware
app.use(function *(next){
  if (this.url.match(/^\/public/)) {
    this.body = 'unprotected\n';
  } else {
    yield next;
  }
});

// Middleware below this line is only reached if JWT token is valid
app.use(koaeula({ secret: 'secret' }));

app.use(function *(){
  if (this.url.match(/^\/api/)) {
    this.body = 'protected\n';
  }
});

app.listen(3000);
