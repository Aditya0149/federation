var request = require('request');
var express = require('express');
var router = express.Router();
var passport = require('../passport-middleware');
var saml = require('passport-saml');
var fs = require('fs');

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
    forceAuthn: true
  
  }, function(profile, done) {
      return done(null, profile); 
  });
  passport.use(samlStrategy);
}

/*
  ALL OF THE ROUTES IN THIS PAGE REQUIRE AN AUTHENTICATED USER
*/

/* GET users listing. */
router.get('/', function(req, res, next) {

  console.log(req.user)

  res.render('saml');
});

// form submit
router.post('/setup',
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


// sso
router.get('/login',
  passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function (req, res) {
    res.redirect('/saml');
  }
);

// assertion URL
router.post('/login/callback',
   passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function(req, res) {
    res.redirect('/');
  }
);

router.get('/logout', function(req, res) {
  return samlStrategy.logout(req, function(err, uri) {
    req.logout();
    return res.redirect(uri);
  });
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



module.exports = router;
