var localStrategy = require("passport-local").Strategy;
var mysql = require("mysql");

var bcrypt = require("bcrypt-nodejs");
var dbconfig = require("./database");
var connection = mysql.createConnection(dbconfig.connection);

connection.query("USE " + dbconfig.database);

module.exports = function(passport) {
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    connection.query("SELECT * from users where id= ?", [id], (err, rows) => {
      done(err, rows[0]);
    });
  });

  passport.use(
    "local-signup",
    new localStrategy(
      {
        usernameField: "username",
        passwordField: "password",
        passReqToCallback: true
      },
      (req, username, password, done) => {
        connection.query(
          "select * from users where username = ?",
          [username],
          (err, rows) => {
            if (err) return done(err);
            if (rows.length) {
              return done(
                null,
                false,
                req.flash("signupMessage", "That is already taken")
              );
            } else {
              var newUserMysql = {
                username: username,
                password: bcrypt.hashSync(password, null, null)
              };

              var insertQuery =
                "Insert into users (username,password) values (?,?)";

              connection.query(
                insertQuery,
                [newUserMysql.username, newUserMysql.password],
                (err, rows) => {
                  newUserMysql.id = rows.insertId;

                  return done(null, newUserMysql);
                }
              );
            }
          }
        );
      }
    )
  );

  passport.use(
    "local-login",
    new localStrategy(
      {
        usernameField: "username",
        passwordField: "password",
        passReqToCallback: true
      },
      (req, username, password, done) => {
        connection.query(
          "Select * from users where username = ?",
          [username],
          (err, rows) => {
            if (err) return done(err);
            if (!rows.length) {
              return done(
                null,
                false,
                req.flash("loginMessage", "No User Found")
              );
            }

            if (!bcrypt.compareSync(password, rows[0].password))
              return done(
                null,
                false,
                req.flash("loginMesage", "Wrong password")
              );

            return done(null, rows[0]);
          }
        );
      }
    )
  );
};
