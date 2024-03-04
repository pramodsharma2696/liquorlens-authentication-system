require('dotenv').config();
const cookieParser = require("cookie-parser");
const multer = require('multer');
const csrf = require("csurf");
const bodyParser = require("body-parser");
const express = require("express");
const admin = require("firebase-admin");
const path = require('path');

const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  databaseURL: process.env.FIREBASE_DATABASEURL
});
const upload = multer({ storage: multer.memoryStorage() }); 
const bucket = admin.storage().bucket();

const csrfMiddleware = csrf({ cookie: { key: "__session", httpOnly: true } });

const PORT = process.env.PORT || 3000;
const app = express();

app.engine("html", require("ejs").renderFile);
// app.use(express.static("static"));
app.use('/static',express.static(path.join(__dirname,'static')));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(csrfMiddleware);

app.all("*", (req, res, next) => {
  var token = req.csrfToken();
  res.cookie("XSRF-TOKEN", token);
  next();
});

function checkAuth(req, res, next) {
  const sessionCookie = req.cookies.session || "";
  admin
    .auth()
    .verifySessionCookie(sessionCookie, true /** checkRevoked */)
    .then((userData) => {
      res.redirect("/profile");
    })
    .catch((error) => {
      next();
    });
}
//Handle file upload
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }
  const file = req.file;
  const fileName = file.originalname;
  const filePath = `report/${fileName}`; // Path in Firebase Storage

  const blob = bucket.file(filePath);

  const blobStream = blob.createWriteStream({
    metadata: {
      contentType: file.mimetype,
    },
  });

  blobStream.on("error", (error) => {
    console.error(error);
    res.status(500).send("Error uploading file.");
  });

  blobStream.on("finish", () => {
    res.status(200).send("File uploaded successfully.");
  });

  blobStream.end(file.buffer);
});



app.get("/profile", function (req, res) {
  const sessionCookie = req.cookies.session || "";

  admin
    .auth()
    .verifySessionCookie(sessionCookie, true /** checkRevoked */)
    .then((userData) => {
      console.log(userData);
      console.log("Logged in:", userData.email)
      res.render("profile.html",{ user: userData});
    })
    .catch((error) => {
      res.redirect("/");
    });
});

app.get("/", checkAuth, function (req, res) {
  res.render("index.html");
});

app.post("/sessionLogin", (req, res) => {
  const idToken = req.body.idToken.toString();

  const expiresIn = 60 * 60 * 24 * 5 * 1000;

  admin
    .auth()
    .createSessionCookie(idToken, { expiresIn })
    .then(
      (sessionCookie) => {
        const options = { maxAge: expiresIn, httpOnly: true };
        res.cookie("session", sessionCookie, options);
        res.end(JSON.stringify({ status: "success" }));
      },
      (error) => {
        res.status(401).send("UNAUTHORIZED REQUEST!");
      }
    );
});

/*
app.post("/sessionRegister", (req, res) => {
  const idToken = req.body.idToken.toString();
  const expiresIn = 60 * 60 * 24 * 5 * 1000;
  firebase
    .auth()
    .createSessionCookie(idToken, { expiresIn })
    .then(
      sessionCookie => {
        const options = { maxAge: expiresIn, httpOnly: true };
        res.cookie("session", sessionCookie, options);
        res.end(JSON.stringify({ status: "Success" }));
      },
      error => {
        res.status(401).send("UNAUTHORIZED REQUEST");
        res.redirect("/");
      }
    );
});

*/
app.get("/sessionLogout", (req, res) => {
  res.clearCookie("session");
  res.redirect("/");
});

app.get("/firebase-config", (req, res) => {
  const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    databaseURL: process.env.FIREBASE_DATABASEURL,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID,
  };
  res.json(firebaseConfig);
});
app.listen(PORT, () => {
  console.log(`Listening on http://localhost:${PORT}`);
});