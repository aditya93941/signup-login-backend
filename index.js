const express = require('express');
const sqlite3 = require('sqlite3');
const cors = require('cors');
const path = require('path');
const {open} = require('sqlite');
const {v4: uuidv4} = require('uuid');
const bcrypt = require('bcryptjs');
const jwtToken = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const port = 3000;

const dbPath = path.join(__dirname, 'database.db');

let db;

const initializingServer = async() =>{
    try{
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        })
        console.log('Database connected');
        app.listen(port, () =>{
            console.log(`Server Started port ${port}`);
        })
    }
    catch(err){
        console.log(err.message);
        process.exit(1);
    }
}


initializingServer();

// Signup

app.post('/signup',async(request, response)=>{
    try{
        const {name, email, password} = request.body
        const user = await db.get(`SELECT * FROM user WHERE email = ?`, [email]);
        if(user){
            return response.json({ok:false,msg:'user already exist'})
        }else{
            const query = `INSERT INTO user VALUES(?,?, ?, ?)`;
            const hashedPassword = await bcrypt.hash(password, 10);
            const res = await db.run(query, [uuidv4(), name, email, hashedPassword]);
            return response.json({ok:true, msg:'user created successfully!'});
        }
    }
    catch(err){
        console.log(err.message);
        return response.json({ok:false, msg: err.message});
    }
})

//Login

app.post('/login',async(request, response)=>{
    try{
        const {email, password} = request.body
        const user = await db.get(`SELECT * FROM user WHERE email = ?`, [email]);
        if(user){
            const isValidPass = await bcrypt.compare(password,user.password);
            if(isValidPass){
                const token = jwtToken.sign({email:user.email}, 'adithya');
                return response.json({ok:true, msg:'Login Success!!', jwtToken:token})
            }else{
                return response.json({ok:false,msg:'wrong password'});
            }
        }else{
            return response.json({ok:false, msg:'user not exist'});
        }
    }
    catch(err){
        console.log(err.message);
        return response.json({ok:false, msg: err.message});
    }
})