var http = require('http');
var fs = require('fs');
var express = require("express");
var dotenv = require('dotenv');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');
var request = require('request');
var path = require('path');

dotenv.load();

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var samlStrategy = new saml.Strategy({
  // authnContext: ["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
  //   "urn:federation:authentication:windows"],
  // URL that goes from the Identity Provider -> Service Provider
  callbackUrl: process.env.CALLBACK_URL,
  // URL that goes from the Service Provider -> Identity Provider
  entryPoint: process.env.ENTRY_POINT,
  // Usually specified as `/shibboleth` from site root
  issuer: process.env.ISSUER,
  identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  // Service Provider private key
  //decryptionPvk: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
  // Service Provider Certificate
  privateCert: fs.readFileSync(__dirname + '/key.pem', 'utf8'),
  // Identity Provider's public key
  cert: fs.readFileSync(__dirname + '/cic_certificate.cer', 'utf8'),
  //validateInResponseTo: false,
  //disableRequestedAuthnContext: true,
  //signatureAlgorithm: 'sha256',
  //digestAlgorithm: 'sha256'
  logoutUrl: 'https://sitaram-mulik.ite1.idng.ibmcloudsecurity.com/idaas/mtfim/sps/idaas/logout',
  logoutCallback: 'http://localhost:4006/login'

}, function(profile, done) {
    //Here save the nameId and nameIDFormat somewhere
    user = {};
    user.nameID = profile.nameID;
    user.nameIDFormat = profile.nameIDFormat;
    return done(null, profile); 
});

passport.use(samlStrategy);

var app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(cookieParser());
app.use(bodyParser());
app.use(session({secret: process.env.SESSION_SECRET}));
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    console.log('Authenticated...');
    return next();
  }
  else {
    console.log('Not Authenticated...');
    return res.redirect('/home');
  }
}

app.get('/',
  ensureAuthenticated, 
  function(req, res) {
    // console.log("------------------------------   start ---------------------------------");
    // console.log(req);
    // console.log("------------------------------   end ---------------------------------");
    //res.send(req.user);
    //res.redirect('/profile');
    res.render('profile', {
      title: 'Profile',
      user: req.user
    });
  }
);

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function (req, res) {
    res.redirect('/');
  }
);

app.get('/home',
  function (req, res) {
    res.render('index', {
      title: 'Login to Gslab',
      user: req.user
    });
  }
);

app.post('/login/callback',
   passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/login/fail', 
  function(req, res) {
    res.status(401).send('Login failed');
  }
);

app.get('/logout', function(req, res) {
  //req.logout();
  //res.redirect('/');

  return samlStrategy.logout(req, function(err, uri) {
    req.logout();
    //res.redirect('/home');
    return res.redirect(uri);
  });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

// //logout
passport.logoutSaml = function(req, res) {
  //Here add the nameID and nameIDFormat to the user if you stored it someplace.
  req.user.nameID = req.user.saml.nameID;
  req.user.nameIDFormat = req.user.saml.nameIDFormat;


  samlStrategy.logout(req, function(err, request){
      if(!err){
          //redirect to the IdP Logout URL
          res.redirect(request);
      }
  });
};


// listen for requests :)
const listener = app.listen(process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
