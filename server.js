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

var samlStrategy;


function setSamlStratergy(metaData) {
  samlStrategy = new saml.Strategy({
    callbackUrl: process.env.CALLBACK_URL,
    entryPoint: metaData.loginUrl,
    issuer: metaData.providerID,
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    privateCert: fs.readFileSync(__dirname + '/key.pem', 'utf8'),
    cert: metaData.cert,
    logoutUrl: metaData.logoutUrl,
    validateInResponseTo: true,
    signatureAlgorithm: 'sha256'
  
  }, function(profile, done) {
      return done(null, profile); 
  });
  passport.use(samlStrategy);
}

var app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
//app.use('/assets', express.static('public'));
app.use(cookieParser());
app.use(bodyParser());
app.use(session({secret: process.env.SESSION_SECRET}));
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  else {
    return res.redirect('/home');
  }
}

app.get('/',
  ensureAuthenticated, 
  function(req, res) {
    let user = {...req.user};
    delete user.issuer;
    console.log('req ', req.user);
    res.render('profile', {
      user: user,
      data: req.session.metaData
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
      user: req.user,
      metaData: req.session.metaData
    });
  }
);

app.post('/setup',
  function (req, res) {
    req.session.metaData = {
      loginUrl: req.body.loginUrl,
      providerID: req.body.providerID,
      cert: req.body.cert,
      logoutUrl: req.body.logoutUrl
    };
    setSamlStratergy(req.session.metaData);
    res.redirect('/home');
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
  return samlStrategy.logout(req, function(err, uri) {
    req.logout();
    return res.redirect(uri);
  });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Incorrect configuration provided...');
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
