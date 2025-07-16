const express = require("express");
const path = require("path");
const kontrol = require("node-fetch");
const cors = require("cors");
require("dotenv").config();
global.ReadableStream = require('stream/web').ReadableStream;  

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname)));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const { router: pikamedRouter, createCronJobs } = require("./routes/pikamed");

app.use("/geogame", require("./routes/geogame"));
app.use("/pikamed", pikamedRouter);

app.get("/", (req, res) => {
  res.send("Server çalışıyor");
});

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------

setInterval(() => {
  kontrol("https://keremkk.glitch.me/status");
}, 5000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  createCronJobs();
  console.log("Çalışıyor");
});
