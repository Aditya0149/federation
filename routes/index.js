var express = require('express');
var router = express.Router();

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  else {
    return res.redirect('/home');
  }
}

router.get('/',
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

router.get('/home',
  function (req, res) {
    res.render('index', {
      user: req.user,
      metaData: req.session.metaData
    });
  }
);

router.get('/login/fail', 
  function(req, res) {
    res.status(401).send('Login failed');
  }
);

module.exports = router;
