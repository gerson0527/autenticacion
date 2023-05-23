const {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    loggedUser,
    login,
  } = require("../controllers/user.controllers");
  const express = require("express");
  const verifyJWT = require("../utils/verifyJWT");
  
  const userRouter = express.Router();
  
  userRouter.route("/").get(verifyJWT, getAll).post(create);
  userRouter.route("/verify/:code").get(verifyCode);
  userRouter.route("/me").get(verifyJWT, loggedUser);
  userRouter.route("/login").post(verifyJWT, login);
  
  userRouter
    .route("/:id")
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(verifyJWT, update);
  
  module.exports = userRouter;