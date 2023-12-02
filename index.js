const express = require('express')
const app = express()
const port = 3000
const bodyParser = require('body-parser');
const db = require('./dbConnection');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const gensalt = bcrypt.genSaltSync(saltRounds); 
const jwt = require('jsonwebtoken'); 

app.use(bodyParser.json());



const isAuthorized = (req,res,next) =>{
  const token = req.headers['authorization'];
  const splittoken = token.split(' ')[1];
  if(!token == null){
    return res.status(401).json({msg:"Unauthorized"});
  }
  jwt.verify(splittoken,'secret',(err,result) =>{
    if(err){
      return res.status(401).json({
        msg:"Unauthorized"
      });
    }
    req.user = result;
    next();
  })
}

app.post('/register',(req,res) =>{
  const {email,username,password} = req.body;
  if(!email||!username||!password){
      return res.status(400).json({
        msg:"Please fill all the fields"
      });
  }

  const queryEmail = "SELECT * FROM tb_user WHERE email=?";
  db.query(queryEmail,[email],(err,result) =>{
      if(err) throw err;
      if(result > 0){
          return res.status(400).json({
            msg:"Email already exists"});
      }

      const query = "INSERT INTO tb_user(email,username,password) VALUES (?,?,?)";
      db.query(query,[email,username,bcrypt.hashSync(password,saltRounds)],(err,result) =>{
          if(err) throw err;
          return res.status(201).json({error:"User registered successfully"});
      })
  })  
  
})

app.post('/login',(req,res) =>{
    const {email,password} = req.body;
    const cekEmail = "SELECT * FROM tb_user WHERE email=?";

    db.query(cekEmail,[email],(err,result) =>{
      if(err) throw err;
      if(result.length === 0){
        return res.status(400).json({
          msg:"Email not found"});
      }
      const cekPassword = bcrypt.compareSync(password,result[0].password);
      if(!cekPassword){
        return res.status(400).json({
          msg:"Password not match"});
      }
      const token = jwt.sign({
        id: result[0].id, 
        email: result[0].email},'secret', { expiresIn: '1d' });

      return res.status(200).json({
        msg:"Login success",
        token
        
      });
    })
})



app.get('/getuser', (req, res) => {
  const query = "SELECT * FROM tb_user";
  db.query(query, (err, result) => {
    if (err) throw err;
    return res.status(200).json({ result });
  });
});


app.get('/profile', isAuthorized,(req, res) => {
  return res.status(200).json({
    user:req.user
  });
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
