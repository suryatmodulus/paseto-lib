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

  if (key.type !== 'public' || key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'secp384r1') {
    throw new TypeError('v3.public verify key must be a public EC P-384 key')
  }

  return key
}

module.exports = async function v3Verify (token, key, { complete = false, buffer = false, assertion, ...options } = {}) {
  key = checkKey(key)
  const i = checkAssertion(assertion)

  const { m, footer } = await verify('v3.public.', token, 'sha384', 96, { key, dsaEncoding: 'ieee-p1363' }, i)

  if (buffer) {
    if (complete) {
      return { payload: m, footer, version: 'v3', purpose: 'public' }
    }

    return m
  }

  const payload = parse(m)
  assertPayload(options, payload)

  if (complete) {
    return { payload, footer, version: 'v3', purpose: 'public' }
  }

  return payload
}
