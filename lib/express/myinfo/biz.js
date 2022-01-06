const _ = require('lodash')
const bodyParser = require('body-parser')
const fs = require('fs')
const jwt = require('jsonwebtoken')
const { pick, partition } = require('lodash')
const path = require('path')

const assertions = require('../../assertions')
const crypto = require('../../crypto')

const consent = require('./consent')

const MOCKPASS_PRIVATE_KEY = fs.readFileSync(path.resolve(__dirname, '../../../static/certs/spcp-key.pem'))
const MOCKPASS_PUBLIC_KEY = fs.readFileSync(path.resolve(__dirname, '../../../static/certs/spcp.crt'))

function config (app, { serviceProvider }) {
  const { verifyMyInfoSignature, pkiBaseString } = crypto(serviceProvider)

  const lookupPerson = allowedAttributes => (req, res) => {
    const requestedAttributes = (req.query.attributes || '').split(',')

    const [attributes, disallowedAttributes] = partition(
      requestedAttributes,
      v => allowedAttributes.includes(v)
    )

    if (disallowedAttributes.length > 0) {
      res.status(401).send({ code: 401, message: 'Disallowed', fields: disallowedAttributes.join(',') })
    } else {
      const persona = assertions.myinfo.biz.personas[req.params.uen]
      res.status(persona ? 200 : 404)
        .send(
          persona
            ? persona
            : { code: 404, message: 'UIN/FIN does not exist in MyInfo.', fields: '' }
        )
      // res.status(persona ? 200 : 404)
      //   .send(
      //     persona
      //       ? pick(persona, attributes)
      //       : { code: 404, message: 'UIN/FIN does not exist in MyInfo.', fields: '' }
      //   )
    }
  }

  app.get('/biz/v2/entity-person/:uen/:uinfin', (req, res) => {
    const [, token] = req.get('Authorization').split(' ')
    const { sub, scope } = jwt.verify(token, MOCKPASS_PUBLIC_KEY, { algorithms: ['RS256'] })

    const splitSub = sub.split("_")
    const uen = splitSub[0]
    const uinfin = splitSub[1]

    if (uen !== req.params.uen) {
      res.status(401).send({ code: 401, message: 'UEN requested does not match logged in user', fields: '' })
    } else {
      lookupPerson(scope)(req, res)
    }

    if (uinfin !== req.params.uinfin) {
      res.status(401).send({ code: 401, message: 'UIN requested does not match logged in user', fields: '' })
    } else {
      lookupPerson(scope)(req, res)
    }
  })

  app.get('/biz/v2/authorise', consent.initBizAuthorization)

  app.post('/biz/v2/token',
    bodyParser.urlencoded({ extended: false, type: 'application/x-www-form-urlencoded' }),
    (req, res) => {
      const tokenTemplate = consent.authorizations[req.body.code]
      if (!tokenTemplate) {
        res.status(400).send({ code: 400, message: 'No such authorization given', fields: '' })
      } else {
        const token = jwt.sign(
          { ...tokenTemplate, auth_time: Date.now() },
          MOCKPASS_PRIVATE_KEY,
          { expiresIn: '1800 seconds', algorithm: 'RS256' }
        )
        res.send({
          access_token: token,
          token_type: 'Bearer',
          expires_in: 1798,
        })
      }
    }
  )

  return app
}

module.exports = config
