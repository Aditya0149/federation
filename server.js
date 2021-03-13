var express = require("express");
var dotenv = require('dotenv');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('./passport-middleware');
var saml = require('passport-saml');
var path = require('path');
var saml = require('./routes/saml');
var home = require('./routes/index');

dotenv.load();

var app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.use('/public', express.static('public'));
app.use(cookieParser());
app.use(bodyParser());
app.use(session({secret: process.env.SESSION_SECRET}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/', home);
app.use('/saml', saml);

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


let port = process.env.PORT || 4000;
// listen for requests :)
const listener = app.listen(port, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
