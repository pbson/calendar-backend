const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require('mongoose')
const { registerValidation, loginValidation } = require('../../validation');
const verify = require('../../middleware/verifyToken')

const User = require("../../models/User");


router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  //VALIDATE
  const { error } = registerValidation(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message)
  }
  try {
    //Check if user already exist
    let findUser = await User.find({ email: req.body.email });
    if (findUser.length > 0) {
      return res.status(400).send('Email already exists')
    }
    //Create user
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(req.body.password, salt);

    const user = new User({
      name: name,
      email: email,
      password: hashPassword,
      isAdmin: false,
    });

    const savedUser = await user.save();
    //Create and sign Token
    const token = jwt.sign({ _id: savedUser._id }, process.env.jwtSecret, {expiresIn:86400});
    res.status(200).header('auth-token', token).send({ auth: true, token: token, user: savedUser });

  } catch (error) {
    res.status(4000).send(error);
  }
});

router.post('/register-admin',async function(req, res) {
  const { name, email, password } = req.body;
  //VALIDATE
  const { error } = registerValidation(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message)
  }
  try {
    //Check if user already exist
    let findUser = await User.find({ email: req.body.email });
    if (findUser.length > 0) {
      return res.status(400).send('Email already exists')
    }
    //Create user
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(req.body.password, salt);

    const user = new User({
      name: name,
      email: email,
      password: hashPassword,
      isAdmin: true,
    });

    const savedUser = await user.save();
    //Create and sign Token
    const token = jwt.sign({ _id: savedUser._id }, process.env.jwtSecret, {expiresIn:86400});
    res.status(200).header('auth-token', token).send({ auth: true, token: token, user: savedUser });

  } catch (error) {
    res.status(4000).send(error);
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  //VALIDATE
  const { error } = loginValidation(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message)
  }
  try {
    //Check if user already exist
    let findUser = await User.findOne({ email: email });
    if (!findUser) {
      return res.status(400).send('Email doesnt exists')
    }
    //check if password is correct
    let isMatch = await bcrypt.compare(password, findUser.password);
    if (!isMatch) {
      return res.status(400).send('Password invalid')
    }
    //Create and sign Token
    const token = jwt.sign({ _id: findUser._id, email: findUser.email }, process.env.jwtSecret);
    console.log(token)
    res.status(200).header('auth-token', token).send({ auth: true, token: token, user: findUser });
  } catch {
    res.status(400).send(error);
  }
});

// logout 
router.post("/logout/", (req, res) => {
  const token = req.query.token;
  try {
    if (token) {
      jwt.verify(token, "secretToken", async (err, userData) => {
        if (err) {
          res.json({
            code: "1004",
            message: "Parameter value is invalid"
          });
        } else {
          const id = userData.user.id
          let user = await User.findOne({ _id: id })
          if (user) {
            if (token === user.token) {
              let a = await User.findOneAndUpdate({ _id: user._id }, { token: "" })
              if (a) {
                return res.json({
                  code: "1000",
                  message: "OK"
                })
              } else {
                return res.json({
                  code: "1001",
                  message: "Can not connect Database"
                })
              }

            } else {
              if (user.token === "" || user.token === null) {
                return res.json({
                  code: "1004",
                  message: "User don't have token in db"
                })
              } else {
                return res.json({
                  code: "1004",
                  message: "Token is invalid"
                })
              }

            }
          } else {
            return res.json({
              code: "9995",
              message: "Don't find user by token"
            })
          }
        }
      });
    } else {
      return res.json(
        {
          code: "1002",
          message: "No have Token"
        }
      )
    }
  } catch (error) {
    return res.json({
      code: "1005",
      message: error
    })
  }

})

//get user info
router.post("/get_user_info", (req, res) => {
  const { token, user_id } = req.query;
  try {
    //Decode token to get user_id
    jwt.verify(token, "secretToken", async (err, userData) => {
      if (err) {
        res.json({
          message: "Token is invalid",
          code: "9998",
        });
      } else {
        let user
        if (user_id) {
          user = await User.findOne({ _id: user_id });
        } else {
          user = await User.findOne({ _id: userData.user.id });
        }
        //Search user with token provided
        if (!user) {
          return res.json({
            message: "Can't find user",
            code: "9995",
          });
        }
        //Check if user is locked
        if (user.locked == 1) {
          return res.json({
            message: "User is locked",
            code: "9995",
          });
        }
        let resData = {
          id: user._id,
          username: user.username,
          created: user.created,
          description: user.description,
          avatar: user.avatar,
          cover_image: user.cover_image,
          address: user.address,
          city: user.city,
          country: user.country,
          listing: user.listing,
          online: user.online
        }
        return res.json({
          code: "1000",
          message: "ok",
          data: resData
        })
      }

    });
  } catch (error) {
    return res.json({
      message: "Server error",
      code: "1001",
    });
  }
})

router.post("/set_user_info", (req, res) => {
  const { token, username, description, avatar, address, city, country, cover_image, link } = req.query;
  try {
    //Decode token to get user_id
    jwt.verify(token, "secretToken", async (err, userData) => {
      if (err) {
        res.json({
          message: "Token is invalid",
          code: "9998",
        });
      } else {
        let user = await User.findOne({ _id: userData.user.id });
        //Search user with token provided
        if (!user) {
          return res.json({
            message: "Can't find user with token provided",
            code: "9995",
          });
        }
        //Check if token match
        if (user.token !== token) {
          return res.json({
            message: "Token is invalid",
            code: "9998",
          });
        }
        //Check if user is locked
        if (user.locked == 1) {
          return res.json({
            message: "User is locked",
            code: "9995",
          });
        }
        if (description.length > 150) {
          return res.json({
            code: "1000",
            message: "Description too long",
          })
        }
        if (avatar.localeCompare('vnhackers.com') == true || cover_image.localeCompare('vnhackers.com') == true) {
          return res.json({
            code: "1000",
            message: "url is prohibited",
          })
        }
      }
      let resData = {
        username: username,
        description: description,
        avatar: avatar,
        cover_image: cover_image,
        address: address,
        city: city,
        country: country,
        listing: listing,
      }

      for (let prop in userData) if (!userData[prop]) delete userData[prop];
      let updateUser = await User.findOneAndUpdate({ _id: userData.user.id }, userData);

      return res.json({
        code: "1000",
        message: "ok",
        data: resData
      })
    })
  } catch (error) {
    return res.json({
      message: "Server error",
      code: "1001",
    });
  }
})

router.post("/set_devtoken", (req, res) => {
  const { token, devtoken } = req.query;
  try {
    //Decode token to get user_id
    jwt.verify(token, "secretToken", async (err, userData) => {
      if (err) {
        res.json({
          message: "Token is invalid",
          code: "9998",
        });
      } else {
        let user = await User.findOne({ _id: userData.user.id });
        //Search user with token provided
        if (!user) {
          return res.json({
            message: "Can't find user with token provided",
            code: "9995",
          });
        }
        //Check if token match
        if (user.token !== token) {
          return res.json({
            message: "Token is invalid",
            code: "9998",
          });
        }
        //Check if user is locked
        if (user.locked == 1) {
          return res.json({
            message: "User is locked",
            code: "9995",
          });
        }

        let updateUser = DeviceToken.findOneAndUpdate({ UserId: user.id }, { DeviceToken: devtoken })

        return res.json({
          code: "1000",
          message: "ok",
          data: {
            userId: updateUser.id,
            DeviceToken: updateUser.DeviceToken
          }
        })
      }

    });
  } catch (error) {
    return res.json({
      message: "Server error",
      code: "1001",
    });
  }
})

router.post("/get_user_friends", (req, res) => {
  const { token, user_id, index, count } = req.query;
  try {
    //Decode token to get user_id
    jwt.verify(token, "secretToken", async (err, userData) => {
      if (err) {
        res.json({
          message: "Token is invalid",
          code: "9998",
        });
      } else {
        let user;
        if (user_id) {
          user = await User.findOne({ _id: user_id });
        } else {
          user = await User.findOne({ _id: userData.user.id });
        }
        //Search user 
        if (!user) {
          return res.json({
            message: "Can't find user",
            code: "9995",
          });
        }
        //Check if user is locked
        if (user.locked == 1) {
          return res.json({
            message: "User is locked",
            code: "9995",
          });
        }
        requestData = await Promise.all(user.ListFriends.map(async friend => {
          let findFriend = await User.findOne({ _id: friend });
          let intersection = user.ListFriends.filter(element => findFriend.ListFriends.includes(element));
          return {
            id: findFriend._id,
            username: findFriend.username,
            avatar: findFriend.avatar,
            same_friends: intersection.length
          }
        }))
        requestData.sort(function (a, b) {
          var textA = a.username.toUpperCase();
          var textB = b.username.toUpperCase();
          return (textA < textB) ? -1 : (textA > textB) ? 1 : 0;
        });

        let responseData = {
          friends: requestData.slice(index, index + count),
          total: user.ListFriends.length
        }
        return res.json({
          code: "1000",
          message: "ok",
          data: responseData
        })
      }

    });
  } catch (error) {
    return res.json({
      message: "Server error",
      code: "1001",
    });
  }
})

router.post("/get_requested_friends", (req, res) => {
  console.log('abc')
  const { token, index, count } = req.query;
  try {
    //Decode token to get user_id
    jwt.verify(token, "secretToken", async (err, userData) => {
      if (err) {
        res.json({
          message: "Token is invalid",
          code: "9998",
        });
      } else {
        let user = await User.findOne({ _id: userData.user.id });
        //Search user 
        if (!user) {
          return res.json({
            message: "Can't find user",
            code: "9995",
          });
        }
        //Check if user is locked
        if (user.locked == 1) {
          return res.json({
            message: "User is locked",
            code: "9995",
          });
        }
        requestData = await Promise.all(user.FriendsRequest.map(async friend => {
          let findFriend = await User.findOne({ _id: friend });
          let intersection = user.ListFriends.filter(element => findFriend.ListFriends.includes(element));
          return {
            id: findFriend._id,
            username: findFriend.username,
            avatar: findFriend.avatar,
            same_friends: intersection.length
          }
        }))
        requestData.sort(function (a, b) {
          var textA = a.username.toUpperCase();
          var textB = b.username.toUpperCase();
          return (textA < textB) ? -1 : (textA > textB) ? 1 : 0;
        });

        let responseData = {
          list_users: requestData.slice(index, index + count),
          total: user.FriendsRequest.length
        }
        console.log(requestData);
        return res.json({
          code: "1000",
          message: "ok",
          data: responseData
        })
      }
    });
  } catch (error) {
    return res.json({
      message: "Server error",
      code: "1001",
    });
  }
})

router.post("/get_list_suggested_friends", (req, res) => {
  console.log('abc')
  const { token, index, count } = req.query;
  try {
    //Decode token to get user_id
    jwt.verify(token, "secretToken", async (err, userData) => {
      if (err) {
        res.json({
          message: "Token is invalid",
          code: "9998",
        });
      } else {
        let user = await User.findOne({ _id: userData.user.id });
        //Search user 
        if (!user) {
          return res.json({
            message: "Can't find user",
            code: "9995",
          });
        }
        //Check if user is locked
        if (user.locked == 1) {
          return res.json({
            message: "User is locked",
            code: "9995",
          });
        }

        let allUser = await User.find({});

        requestData = await Promise.all(allUser.map(async (user) => {
          let findFriend = await User.findOne({ _id: user });
          let intersection = user.ListFriends.filter(element => findFriend.ListFriends.includes(element));

          return {
            id: user.id,
            username: user.username,
            avatar: user.avatar,
            same_friends: intersection.length
          }
        }))

        let responseData = {
          list_users: requestData.slice(index, index + count),
        }
        console.log(requestData);
        return res.json({
          code: "1000",
          message: "ok",
          data: responseData
        })
      }
    });
  } catch (error) {
    return res.json({
      message: "Server error",
      code: "1001",
    });
  }
})
module.exports = router;
