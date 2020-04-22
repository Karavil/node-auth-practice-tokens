import { PrismaClient } from "@prisma/client";

import express, { Request, Response } from "express";
import bodyParser from "body-parser";

import jwt from "jsonwebtoken";

// Load our .env file
require("dotenv").config();

// Create a prisma client to deal with our database
const prisma = new PrismaClient();
// Create an express client to deal with http requests
const app = express();

// User interface without sensitive information
interface User {
   id: number;
   username: string;
}

// Extend the express library request to include a decoded user
interface AuthenticatedRequest extends express.Request {
   decodedUser?: User;
}

// Generate a token that will expire in 7 days for user access
const generateAccessToken = (user: User) => {
   return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET as string, {
      expiresIn: "7d",
   });
};

// Authenticator middleware that makes sure the user has a valid token
const authenticator = (
   req: AuthenticatedRequest,
   res: express.Response,
   next: express.NextFunction
) => {
   // If there is no token, the user is not allowed to access this route
   const token = req.headers.authorization;
   if (!token) return res.sendStatus(401);

   // If there is a token, decrypt it and make sure it's valid.
   jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET as string,
      (error: any, decodedToken: any) => {
         // There is an error while decoding object, stop process
         if (error) return res.sendStatus(403);

         // Convert the decoded token to user object and store it in the request
         const user = decodedToken as User;
         req.decodedUser = user;

         // User token is decoded, the function after this middleware can be executed
         next();
      }
   );
};

// All requests will have a JSON body, so we have to parse it
app.use(bodyParser.json());

// Route for fetching all users in the database
app.get("/api/users", authenticator, async (req: AuthenticatedRequest, res) => {
   console.log(req.decodedUser);
   const users = await prisma.user.findMany();
   res.status(200).json(users);
});

// Login route
app.post("/api/login", async (req, res) => {
   // Search for the user in our database
   const user = await prisma.user.findOne({
      where: {
         username: req.body.username,
      },
   });

   // If there is no user found, send 404 error
   if (!user) return res.status(404).json("Username not found");
   // If the user password does not match, send error
   if (user.password !== req.body.password)
      return res.status(400).json("Invalid password");
   // If user exists and passwords match, generate token
   const token = generateAccessToken({
      id: user.id,
      username: user.username,
   });

   // After the token is generated, send it so the user can store it
   return res.json(token);
});

// Register route
app.post("/api/register", async (req, res) => {
   // Not hashing passwords here because this is just for token practice
   const newUser = await prisma.user.create({
      data: {
         username: req.body.username,
         password: req.body.password,
      },
   });
   res.status(201).json({ message: `User (${newUser.username}) created.` });
});

const server = app.listen(5000, () =>
   console.log("🚀 Server ready at: http://localhost:5000\n")
);
