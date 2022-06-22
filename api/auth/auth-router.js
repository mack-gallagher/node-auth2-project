const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model');
const jwt = require('jsonwebtoken');

const bcrypt = require('bcryptjs');


function generateToken(user) {
  const payload = {
                    subject: user.user_id, 
                    username: user.username,
                    role_name: user.role_name,
                  };
  const options = {
                    expiresIn: '1d',
                  }

  return jwt.sign(payload, JWT_SECRET, options);
}

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */


  const hash = bcrypt.hashSync(req.body.password,12);

  req.body.password = hash;

  console.log("incoming req.body:");
  console.log(req.body);

  User.add(req.body)
    .then(result => {
      res.status(201).json(result);
    })

});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  
  /* @ FUTURE!MACK: HI! SORRY! PLEASE VALIDATE PASSWORD HERE. THANK YOU! */

  User.find()
    .then(result => {

      let user = '';

      for (let i = 0; i < result.length; i++) {

        if (result[i].password 
            && result[i].username
            && result[i].username === req.body.username
            && bcrypt.compareSync(req.body.password,result[i].password)) {
          user = result[i];
        }
        
      }
  if (!user || user.username !== req.body.username) {
        res.status(401).json({ message: 'invalid credentials' });
        return;
      } else {
        const token = generateToken(user);

        res.status(200).json({
          message: `${user.username} is back!`, 
          token,
        });


      }
      
    })

});

module.exports = router;
