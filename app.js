var express = require('express')
  , passport = require('passport')
  , flash = require('connect-flash')
  , util = require('util')
  , LocalStrategy = require('passport-local').Strategy
  , TwitterStrategy = require('passport-twitter').Strategy
  , FacebookStrategy = require('passport-facebook').Strategy
  , GoogleStrategy = require('passport-google').Strategy
  , LinkedInStrategy = require('passport-linkedin').Strategy
  , GitHubStrategy = require('passport-github').Strategy
  , http = require('http')
  , configs = require('./conf.js')
  , Mongolian = require("mongolian")
  , mongolian = new Mongolian(configs.DB_URL)
  , app = express()
;

console.log(configs);

// Get database
bd = mongolian.db(configs.DB);
bd.auth(configs.DB_USER, configs.DB_PASS);
var posts = bd.collection("posts");
var postsdeux = bd.collection("collection");
var usersdb = bd.collection("users");


app.bd = bd;
app.posts = posts;
app.postsdeux = postsdeux;
app.usersdb = usersdb;

function findById(id, fn, done) {
      var type="";
      app.usersdb.findOne({ id:id }, function(err, user) {
            if(err === null)       {
                fn(null, user);
            }  else {
                fn(new Error('User ' + id + ' does not exist'));
                done(null, id);
            }

        });
}

function findByUsername(username, fn) {

    app.usersdb.findOne({ username:username }, function(err, user) {

        if(err !== null)       {
            return fn(null, null);
        }  else {
            return fn(null, user);
        }

    });
}

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser(function(user, done) {
  done(null, user.id);

});


passport.deserializeUser(function(id, done) {
    findById(id, function (err, user) {
        done(err, user);
    }, done);
});


// Use the LocalStrategy within Passport.
//   Strategies in passport require a `verify` function, which accept
//   credentials (in this case, a username and password), and invoke a callback
//   with a user object.  In the real world, this would query a database;
//   however, in this example we are using a baked-in set of users.
passport.use(new LocalStrategy(
  function(username, password, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      
      // Find the user by username.  If there is no user with the given
      // username, or the password is not correct, set the user to `false` to
      // indicate failure and set a flash message.  Otherwise, return the
      // authenticated `user`.
      findByUsername(username, function(err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false, { message: 'Unknown user ' + username }); }
        if (user.password != password) { return done(null, false, { message: 'Invalid password' }); }
        return done(null, user);
      })
    });
  }
));


passport.use(new TwitterStrategy({
        consumerKey: configs.TWITTER_CONSUMER_KEY,
        consumerSecret: configs.TWITTER_CONSUMER_SECRET,
        callbackURL: configs.BASE_URL+"auth/twitter/callback"
    },
    function(token, tokenSecret, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's Twitter profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the Twitter account with a user record in your database,
            // and return that user instead

            usersdb.insert({
                id: profile.id,
                type: "twitter",
                username: profile.username,
                password: "login_twitter",
                email: "Non disponible"
            });

            return done(null, profile);
        });
    }
));

//   Use the FacebookStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Facebook
//   profile), and invoke a callback with a user object.
passport.use(new FacebookStrategy({
        clientID: configs.FACEBOOK_APP_ID,
        clientSecret: configs.FACEBOOK_APP_SECRET,
        callbackURL: configs.BASE_URL+"auth/facebook/callback"
    },
    function(accessToken, refreshToken, profile, done) {



        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's Facebook profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the Facebook account with a user record in your database,
            // and return that user instead.

            usersdb.insert({
                id: profile.id,
                type: "facebook",
                username: profile.username,
                password: "login_facebook",
                email: "Non disponible"
            });


            return done(null, profile);
        });
    }
));


passport.use(new GoogleStrategy({
        returnURL: configs.BASE_URL+"auth/google/return",
        realm: configs.BASE_URL
    },
    function(identifier, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's Google profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the Google account with a user record in your database,
            // and return that user instead.
            profile.id = identifier;

            usersdb.insert({
                id: profile.id,
                type: "google",
                username: profile.displayName,
                password: "login_google",
                email: profile.emails[0].value
            });

            return done(null, profile);
        });
    }
));

// Use the LinkedInStrategy within Passport.
//   Strategies in passport require a `verify` function, which accept
//   credentials (in this case, a token, tokenSecret, and LinkedIn profile), and
//   invoke a callback with a user object.
passport.use(new LinkedInStrategy({
        consumerKey: configs.LINKEDIN_API_KEY,
        consumerSecret: configs.LINKEDIN_SECRET_KEY,
        callbackURL: configs.BASE_URL+"auth/linkedin/callback"
    },
    function(token, tokenSecret, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's LinkedIn profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the LinkedIn account with a user record in your database,
            // and return that user instead.

            usersdb.insert({
                id: profile.id,
                type: "linkedin",
                username: profile.displayName,
                password: "login_linkedin",
                email: "Non disponible"
            });

            return done(null, profile);
        });
    }
));


// Use the GitHubStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and GitHub
//   profile), and invoke a callback with a user object.
passport.use(new GitHubStrategy({
        clientID: configs.GITHUB_CLIENT_ID,
        clientSecret: configs.GITHUB_CLIENT_SECRET,
        callbackURL: configs.BASE_URL+"auth/github/callback"
    },
    function(accessToken, refreshToken, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's GitHub profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the GitHub account with a user record in your database,
            // and return that user instead.
            console.log(profile);
            usersdb.insert({
                id: profile.id,
                type: "github",
                username: profile.username,
                password: "login_github",
                email: profile.emails[0].value
            });

            return done(null, profile);
        });
    }
));

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.engine('ejs', require('ejs-locals'));
  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' }));
  app.use(flash());
  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
  //app.use(require('less-middleware')({ src: __dirname + '/public' }));
});


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user, message: req.flash('error') });
});


// POST /login
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
//
//   curl -v -d "username=bob&password=secret" http://127.0.0.1:3000/login
app.post('/', passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    });

app.post('/login', passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    });
// POST /login
//   This is an alternative implementation that uses a custom callback to
//   acheive the same functionality.
/*
 app.post('/login', function(req, res, next) {
 passport.authenticate('local', function(err, user, info) {
 if (err) { return next(err) }
 if (!user) {
 req.flash('error', info.message);
 return res.redirect('/login')
 }
 req.logIn(user, function(err) {
 if (err) { return next(err); }
 return res.redirect('/users/' + user.username);
 });
 })(req, res, next);
 });
 */

app.get('/auth/twitter', passport.authenticate('twitter'),
    function(req, res){
        // The request will be redirected to Twitter for authentication, so this
        // function will not be called.
    });

app.get('/auth/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    }
);

// GET /auth/facebook
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Facebook authentication will involve
//   redirecting the user to facebook.com.  After authorization, Facebook will
//   redirect the user back to this application at /auth/facebook/callback
app.get('/auth/facebook', passport.authenticate('facebook'),
    function(req, res){
        // The request will be redirected to Facebook for authentication, so this
        // function will not be called.
    });
// GET /auth/facebook/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    });


// GET /auth/google
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Google authentication will involve redirecting
//   the user to google.com.  After authenticating, Google will redirect the
//   user back to this application at /auth/google/return
app.get('/auth/google', passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        res.redirect('/');
    });

// GET /auth/google/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/google/return', passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        res.redirect('/');
    });



// GET /auth/linkedin
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in LinkedIn authentication will involve
//   redirecting the user to linkedin.com.  After authorization, LinkedIn will
//   redirect the user back to this application at /auth/linkedin/callback
app.get('/auth/linkedin', passport.authenticate('linkedin'),
    function(req, res){
        // The request will be redirected to LinkedIn for authentication, so this
        // function will not be called.
    });

// GET /auth/linkedin/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: '/login' }),
    function(req, res) {
        res.redirect('/');
    });


// GET /auth/github
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in GitHub authentication will involve redirecting
//   the user to github.com.  After authorization, GitHubwill redirect the user
//   back to this application at /auth/github/callback
app.get('/auth/github', passport.authenticate('github'),
    function(req, res){
        // The request will be redirected to GitHub for authentication, so this
        // function will not be called.
    });

// GET /auth/github/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login' }),
    function(req, res) {
        res.redirect('/');
    });


app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.listen(3000);


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}

console.log('Node Version: ' + process.version);
