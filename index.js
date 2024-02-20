const express = require("express");
const app = express();
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const cookieParser = require("cookie-parser");
const authRoute = require("./routes/auth.js");
const ownRoute = require("./routes/own.js");
const postRoute = require("./routes/posts.js");
const commentRoute = require("./routes/comments.js");

//database
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    console.log("database is connected successfully!");
  } catch (err) {
    console.log(err);
  }
};

//middleware
dotenv.config();
app.use(express.json());
app.use("/images", express.static(path.join(__dirname, "/images")));
// Allow requests from http://localhost:5173
app.use(
  cors({
    origin: "https://glistening-wisp-64952b.netlify.app/",
    credentials: true, // Include credentials in CORS request
  })
);
app.use(cookieParser());
app.use("/api/auth", authRoute);
app.use("/api/own", ownRoute);
app.use("/api/posts", postRoute);
app.use("/api/comments", commentRoute);
app.use("/", (req, res) => {
  res.status(200).send("hii");
});

//image upload
const storage = multer.diskStorage({
  destination: (req, file, fn) => {
    fn(null, "images");
  },
  filename: (req, file, fn) => {
    fn(null, req.body.image);
    // fn(null,"image2.jpg")
  },
});

const upload = multer({ storage: storage });
app.post("/api/upload", upload.single("file"), (req, res) => {
  // console.log(req.body)
  res.status(200).json("Image uploaded successfully!");
});

app.listen(process.env.PORT, () => {
  connectDB();
  console.log("app is running on port " + process.env.PORT);
});
