const {
  createPublicKey,
  KeyObject
} = require('crypto')

const assertPayload = require('../help/assert_payload')
const parse = require('../help/parse_paseto_payload')
const checkAssertion = require('../help/check_assertion')
const verify = require('../help/verify')

function checkKey (key) {
  if (!(key instanceof KeyObject) || key.type === 'private') {
    key = createPublicKey(key)
  }

  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('v4.public verify key must be a public ed25519 key')
  }

  return key
}

module.exports = async function v4Verify (token, key, { complete = false, buffer = false, assertion, ...options } = {}) {
  key = checkKey(key)
  const i = checkAssertion(assertion)

  const { m, footer } = await verify('v4.public.', token, undefined, 64, key, i)

  if (buffer) {
    if (complete) {
      return { payload: m, footer, version: 'v4', purpose: 'public' }
    }

    return m
  }

  const payload = parse(m)
  assertPayload(options, payload)

  if (complete) {
    return { payload, footer, version: 'v4', purpose: 'public' }
  }

  return payload
}
