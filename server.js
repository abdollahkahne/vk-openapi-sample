const express=require("express");
const expressSession=require("express-session");
const cookieParser=require("cookie-parser");
const {OpenIDClient}=require("vk-auth-library");
require("dotenv").config();

const app=express();
app.set("port",process.env.PORT||3000);
const port=app.get("port");

app.set("secret",process.env.SECRET||"secret_passcode");

app.use(express.static("public"));
app.use(express.urlencoded({
    extended:false
}));
app.use(express.json());

//Add Session Related middlewares
app.use(cookieParser(app.get("secret")));

app.use(expressSession({
    secret:app.get("secret"),
    cookie:{
        maxAge:4000000
    },
    saveUninitialized:false,
    resave:false 
}));

//Login API
app.post("/auth/vk",(req,res)=>{
    
    const data=req.body.data;
    if (!data || !data.sig) {
       res.status(400).json({success:false,message:"session object should be provided"});
    }
    const client_id=process.env.VK_CLIENT_ID;
    const client_secret=process.env.VK_CLIENT_SECRET;
    const service_token=process.env.VK_SERVICE_TOKEN;
    const client=OpenIDClient(client_id,client_secret,service_token);
    const { expire, mid, secret, sid, sig }=data;
    client.verifyUserData({ expire, mid, secret, sid, sig }).then(result=>{
        req.session.user_id=mid;
        req.session.user=JSON.stringify(result.user);
        res.cookie("vkAuth","vk").json({success:true,user:result.user});
    }).catch(err=>res.status(401).json({success:false,message:"Something is wrong"}));

});

//Middlewares that check user login and then allow to forward in case of lohin authenticated
app.use((req,res,next)=>{
    if (req.session.user) {
        req.user=JSON.parse(req.session.user);
        next();
    }
    else {
        res.status(401).send("Please login first from <a href='/'>login page</a>");   
    }
     
})

app.get("/sensitive",(req,res)=>{
    res.send(`Sensitive Information is placed Here,Dear ${req.user.first_name}` );
});

app.get("/auth/signout",(req,res)=>{
    req.session.destroy();
    res.clearCookie("vkAuth").json({success:true,message:"You logged In successfully"});
});

app.get("*",(req,res)=>{res.json(req.user)});




const server=app.listen(port,()=>{
    console.log(`Server Started at http://localhost:${port}`);
});
