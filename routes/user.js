const express = require('express')
const {check, validationResult} = require('express-validator/check')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const router = express.Router() // eslint-disable-line new-cap

const auth = require('../middleware/auth')

module.exports = ({user}) => {
  const UserModel = user

  router.post(
    '/signup',
    [
      check('email', 'Please enter a valid email').isEmail(),
      check('password', 'Please enter a valid password').isLength({
        min: 6
      })
    ],
    async (req, res) => {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array()
        })
      }

      const {password, email} = req.body

      try {
        let user = await UserModel.findOne({email})

        console.table(user)
        if (user) {
          return res.status(400).json({
            msg: 'User Already Exists'
          })
        }

        user = new UserModel({
          email,
          password
        })

        const salt = await bcrypt.genSalt(10)
        user.password = await bcrypt.hash(password, salt)

        await user.save()

        const payload = {
          user: {
            id: user.id
          }
        }

        jwt.sign(
          payload,
          'randomString',
          {
            expiresIn: 10000
          },
          (err, token) => {
            if (err) {
              throw err
            }

            res.status(200).json({
              token
            })
          }
        )
      } catch (error) {
        console.log(error.message)
        res.status(500).send('Error while saving user')
      }
    })

  router.post(
    '/login',
    [
      check('email', 'Please enter a valid email').isEmail(),
      check('password', 'Please enter a valid password').isLength({
        min: 6
      })
    ],
    async (req, res) => {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array()
        })
      }

      const {email, password} = req.body
      try {
        const user = await UserModel.findOne({
          email
        })
        if (!user) {
          return res.status(400).json({
            message: 'User Not Exist'
          })
        }

        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
          return res.status(400).json({
            message: 'Incorrect Password !'
          })
        }

        const payload = {
          user: {
            id: user.id
          }
        }

        jwt.sign(
          payload,
          'secret',
          {
            expiresIn: 3600
          },
          (err, token) => {
            if (err) {
              throw err
            }

            res.status(200).json({
              token
            })
          }
        )
      } catch (error) {
        console.error(error)
        res.status(500).json({
          message: 'Server Error'
        })
      }
    }
  )

  router.get('/me', auth, async (req, res) => {
    try {
      // Request.user is getting fetched from Middleware after token authentication
      const user = await UserModel.findById(req.user.id)
      res.json(user)
    } catch (error) {
      if (error) {
        console.log(error)
        res.status(500).send('Error while fetching details!')
      }

      res.send({message: 'Error in Fetching user'})
    }
  })


  return router
}
