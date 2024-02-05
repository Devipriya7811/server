const express = require('express')
const app = express()
const mongoose=require('mongoose')
const dotenv = require('dotenv')
const cors = require('cors')
const multer = require('multer')
const path = require('path')
const cookieParser = require('cookie-parser')
const authRoute = require('../server/routes/auth')
const ownRoute = require('./routes/own')
const postRoute = require('./routes/posts')
const commentRoute = require('./routes/comments')



//database
const connectDB=async()=>{
    try {
        await mongoose.connect(process.env.MONGO_URL)
        console.log("database is connected successfully!")
    } catch (err) {
        console.log(err)
    }
}



//middleware
dotenv.config()
app.use(express.json())
app.use("/images",express.static(path.join(__dirname,"/images")))
app.use(cors())
app.use(cookieParser())
app.use("/api/auth",authRoute)
app.use("/api/own",ownRoute)
app.use("/api/posts",postRoute)
app.use("/api/comments",commentRoute)


//image upload
const storage=multer.diskStorage({
    destination:(req,file,fn)=>{
        fn(null,"images")
    },
    filename:(req,file,fn)=>{
        fn(null,req.body.image)
        // fn(null,"image2.jpg")
    }
})

const upload = multer({storage:storage})
app.post("/api/upload",upload.single("file"),(req,res)=>{
    // console.log(req.body)
    res.status(200).json("Image uploaded successfully!")
})

app.listen(process.env.PORT,()=>{
    connectDB()
    console.log("app is running on port " + process.env.PORT)
})
