const jwt = require("jsonwebtoken");
const { SECRET } = require("../configs/server.configs");
const { userStatus, userTypes } = require("../utils/constant");
const userModel = require("../models/user.model");



const verifyToken = (req,res,next)=>{

    let token = req.headers['x-access-token'];

    if(!token){
        return res.status(403).send({message:"No Token Provided"});
    }
    
    jwt.verify(token, SECRET, (err,payload)=>{

        if(err){
            return res.status(401).send({message:"Invalid access token Token provided"});
        }

        req.userId = payload.userId;

        next();
    })

}


const isAdmin = async (req,res,next)=>{

    const {userId} = req;

    try{
        const user = await userModel.findOne({userId});

        if(user.userType===userTypes.admin){
            next();
           return;
        }

        return res.status(403).send({message:"You need to have admin permission to access this route"});

    }catch(err){
            return res.status(500).send({message:"Internal Server Error"});
    }

}

module.exports={
    verifyToken,
    isAdmin
}