'use strict';
const bcrypt = require('bcryptjs')
const AWS = require('aws-sdk')
const jwt = require('jsonwebtoken')

module.exports.login = async (event, context) => {
  const body = JSON.parse(event.body)

  const queryUserParams = {
    TableName: process.env.DYNAMODB_USER_TABLE,
    KeyConditionExpression: '#username = :username',
    ExpressionAttributeNames: {
      '#username': 'pk'
    },
    ExpressionAttributeValues: {
      ':username': body.username
    }
  }

  let userResult = {}
  try {
    const dynamodb = new AWS.DynamoDB.DocumentClient()
    userResult = await dynamodb.query(queryUserParams).promise()
  } catch (queryError) {
    console.log('There was an error attempting to retrieve the user')
    console.log('queryError', queryError)
    console.log('queryUserParams', queryUserParams)
    return new Error('There was an error retrieving the user')
  }

  if (typeof userResult.Items !== 'undefined' &&
    userResult.Items.length === 1) {
    const compareResult = bcrypt.compareSync(body.password, userResult.Items[0].password)
    if (compareResult) {
      let token = jwt.sign({
        username: userResult.Items[0].pk
      }, process.env.JWT_SECRET)
      return {
        statusCode: 200,
        body: JSON.stringify({
          token: token
        })
      }
    }
  }
  return {
    statusCode: 404
  };
};
