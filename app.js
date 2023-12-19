require('dotenv').config();

const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const jtw = require('jsonwebtoken');
const port = 3000;

//config json

app.use(express.json());

//models

const User =  require('./models/user');


//Private route

app.get('/user/:id', checktoken, async (req, res) => {
  const id = req.params.id  //quando o id vem da url a gente tem que usar esse mérodo

  const user = await User.findById(id, '-password');

  if(!user){
    return res.status(404).json({msg: 'usuário não encontrado na base'});

  }

  res.status(200).json({ user });

});

// função check token 
function checktoken(req, res, next) {

  const authheader = req.headers['authorization'];
  const token = authheader && authheader.split("")[1]

  if(!token) {

    return res.status(401).json({ msg: "acesso negado!"})

  }

  try {
    const secret = process.env.SECRET
    jtw.verify(token, secret);

    next();
    
  } catch (error) {
    res.status(400).json({ msg: 'token inválido!'});
    
  }

}

//post para cadastrar user

app.post('/register', async(req, res) => {
  
  const {name, email, password, confirmpassword} = req.body;  

  //validation

  if(!name) {
    return res.status(422).json({msg: "O nome é obrigatório"});

  }
  if(!email) {
    return res.status(422).json({msg: "O email é obrigatório"});

  }
  if(!password) {
    return res.status(422).json({msg: "O password é obrigatório"});

  }
  if(password !== confirmpassword) {
    return res.status(422).json({msg: "as senhas não conferem"});

  }

  //check if email exist

const userExist = await User.findOne({ email: email})

if(userExist) {
  return res.status(422).json({msg: "please use another email"});

}

//create password
const salt = await bcryptjs.genSalt(12);
const  passwordhash = await bcryptjs.hash(password, salt);


//create user

const user = new User({
  name,
  email,
  password: passwordhash,

});

try {

  await user.save()

  res.status(201).json({msg: 'user created sucessufly!'});

  
} catch (error) {

  console.log(error);
  res.status(500).json({msg: 'acoonteceu um erro no server, tente mais tarde!'});
}


});


app.post('/login', async (req, res) => {

const { email, password} = req.body

//validation

if(!email) {
  return res.status(422).json({msg: "O email é obrigatório"});

}
if(!password) {
  return res.status(422).json({msg: "O password é obrigatório"});

}

//check if email exist

const user = await User.findOne({ email: email})

if(!user) {
  return res.status(422).json({msg: "usuário não encontrado!"});

}

//check if password match

const passwordvalidation = await bcryptjs.compare(password, user.password)

if(!passwordvalidation) {
  return res.status(422).json({msg: "Senha inválida!"});

}

try {

  const secret = process.env.SECRET

  const token = jtw.sign(
    {id: user._id,
    
    },
    secret,
  )

  res.status(200).json({msg: "autentificação realizada com sucesso", token})
  

  
} catch (error) {

  console.log(error);
  res.status(500).json({msg: 'acoonteceu um erro no server, tente mais tarde!'});
}





});




//credenciais

const dbUser = process.env.DB_USER
const pass = process.env.DB_PASS



mongoose.connect(`mongodb+srv://${dbUser}:${pass}@cluster0.w6kbf1c.mongodb.net/?retryWrites=true&w=majority`).then(() => {

  app.listen(port, () => {
   console.log(`Server is running on http://localhost:${port}`);
  });
  

}).catch((err) => console.log(err)); 


