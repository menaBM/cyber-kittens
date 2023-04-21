const express = require('express');
const app = express();
const { User, Kitten } = require('./db');
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")

const SALT_COUNT = 10

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.get('/', async (req, res, next) => {
  try {
    res.send(`
      <h1>Welcome to Cyber Kittens!</h1>
      <p>Cats are available at <a href="/kittens/1">/kittens/:id</a></p>
      <p>Create a new cat at <b><code>POST /kittens</code></b> and delete one at <b><code>DELETE /kittens/:id</code></b></p>
      <p>Log in via POST /login or register via POST /register</p>
    `);
  } catch (error) {
    console.error(error);
    next(error)
  }
});

// Verifies token with jwt.verify and sets req.user
// TODO - Create authentication middleware
app.use( (req,res,next)=>{
  if (req.url === "/register" || req.url === "/login"){
    return next()
  }
  let auth = req.header("Authorization")
  if(auth){
    let [,token] = auth.split(" ")
    try{
      req.user = jwt.verify(token, process.env.JWT_SECRET)
      next()
    }catch(error){
      res.sendStatus(401)
      return
    }
  }else{
    res.set("WWW-Authenticate", "Bearer")
    res.sendStatus(401)
    return
  }
})


// POST /register
// OPTIONAL - takes req.body of {username, password} and creates a new user with the hashed password
app.post("/register", async(req,res,next)=>{
  const hash = await bcrypt.hash(req.body.password, SALT_COUNT)
  let user = await User.create({username:req.body.username, password:hash})
  let token = jwt.sign(user.username, process.env.JWT_SECRET)
  res.status(200).send({"message":"success",token})
  return
})


// POST /login
// OPTIONAL - takes req.body of {username, password}, finds user by username, and compares the password with the hashed version from the DB
app.post("/login", async(req,res)=>{
  console.log("here")
  const user = await User.findOne({where:{username:req.body.username}})
  const matches = await bcrypt.compare(req.body.password, user.password)
  if (matches){
    let token = jwt.sign(user.username, process.env.JWT_SECRET)
    res.status(200).send({token,"message":"success"})
  }else{
    res.sendStatus(401)
  }
})

// GET /kittens/:id
// TODO - takes an id and returns the cat with that id
app.get("/kittens/:id", async(req,res,next)=>{
  try{
    let cat = await Kitten.findOne({where:{id : req.params.id}, include:{model:User} })
    if (!cat){ 
      res.sendStatus(404)
      return 
    }else{  
      if (req.user.id === cat.ownerId){
        let kitten = { age:cat.age, color:cat.color, name:cat.name}
        res.send(kitten) 
        return
      }else{
        res.sendStatus(403)
        return
      }
    }
  }catch(err){
    next(err)
  }
})

// POST /kittens
// TODO - takes req.body of {name, age, color} and creates a new cat with the given name, age, and color
app.post("/kittens", async(req,res,next)=>{
  let {name, age, color} = await Kitten.create({name: req.body.name, age:req.body.age, color: req.body.color, ownerId: req.user.id})
  res.status(201).send({name,age,color})
})

// DELETE /kittens/:id
// TODO - takes an id and deletes the cat with that id
app.delete("/kittens/:id", async(req,res,next)=>{
    let cat = await Kitten.findOne({where: {id:req.params.id, ownerId:req.user.id}})
    if (cat) {
      await cat.destroy()
      res.sendStatus(204)
    }
    else{ res.sendStatus(401)}
})

// error handling middleware, so failed tests receive them
app.use((error, req, res, next) => {
  console.error('SERVER ERROR: ', error);
  if(res.statusCode < 400) res.status(500);
  res.send({error: error.message, name: error.name, message: error.message});
});

// we export the app, not listening in here, so that we can run tests
module.exports = app;
