const express = require('express')
const jwt = require('jsonwebtoken')
const dbConnect = require('./db/dbConnect')
const bcrypt = require('bcrypt')
const User = require('./db/userModel')
const auth = require('./auth')

const app = express()

// execute database connection
dbConnect();
app.use(express.json())
// Curb Cores Error by adding a header here
app.use((req, res, next) => {
     res.setHeader("Access-Control-Allow-Origin", "*");
     res.setHeader(
       "Access-Control-Allow-Headers",
       "Origin, X-Requested-With, Content, Accept, Content-Type, Authorization"
     );
     res.setHeader(
       "Access-Control-Allow-Methods",
       "GET, POST, PUT, DELETE, PATCH, OPTIONS"
     );
     next();
   });
// create register
app.post('/register', async (req, res) => {
    // hash the password
   const {email, password} = req.body;

   const salt = await bcrypt.genSalt();
   const hashPassword = await bcrypt.hash(password, salt)

   const newUser = new User({
        email,
        password: hashPassword
   });
   try {
        await newUser.save();
        return res.status(201).json(newUser)
   } catch (error) {
        return res.status(500).json(error)
    
   }
})
// login end point
app.post('/login', (req, res) => {
     // check if email exist
     User.findOne({ email: req.body.email})

     // if email exists
     .then((user) =>{
          //compare the password entered and hashed password found
          bcrypt.compare(req.body.password, user.password)

          // if the password match
          .then((passwordCheck)=> {
               

               // check if password matches
               if(!passwordCheck){
                    return res.status.apply(400).send({
                         message: "Passwords does not match",
                         error,
                    });
               }

               // create JWT TOKEN
               const token = jwt.sign(
                    {
                       userId: user._id,
                       userEmail: user.email,
                    },
                    "RANDOM-TOKEN",
                    {
                         expiresIn: "24h"
                    }
               );
          // return success response
          res.status(200).send({
               message: "Login Successful",
               email: user.email,
               token,
               });
          }).catch((error) => {
               res.status(400).send({
                    message: "Password does not match",
                    error,
               })
          })
     }).catch((error) => {
          res.status(400).send({
               message: "Email not found",
               error,
          })
     })
})

// authentication endpoint
app.get("/auth-endpoint",auth, (request, response) => {
     response.json({ message: "You are authorized to access me" });
   });
// free endpoint
app.get("/free-endpoint", (request, response) => {
     response.json({ message: "You are free to access me anytime" });
   });

app.listen(process.env.PORT, ()=>{
    console.log(`server running on port ${process.env.PORT} `)
})