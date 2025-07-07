const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fs = require('fs');
const users = require('../users.json');

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  let user = users.find(u => u.googleId === profile.id);
  if (!user) {
    user = {
      id: Date.now(),
      googleId: profile.id,
      username: profile.displayName,
      email: profile.emails[0].value,
      role: 'user'
    };
    users.push(user);
    fs.writeFileSync('./users.json', JSON.stringify(users, null, 2));
  }
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});
