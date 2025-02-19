import { LogLevel } from '@credo-ts/core'
import bodyParser from 'body-parser'
import express from 'express'

import { createRestAgent, setupApp } from '../src/index'

const run = async () => {
  const agent = await createRestAgent({
    label: 'Aries Test Agent',
    inboundTransports: [
      {
        transport: 'http',
        port: 5000,
      },
    ],
    logLevel: LogLevel.debug,
    endpoints: ['https://tunnel.factorlabs.pl'],
    walletConfig: {
      id: 'test-agent',
      key: 'test-agent',
    },
  })

  const app = express()
  const jsonParser = bodyParser.json()

  app.get('/greeting', jsonParser, (_, res) => {
    const config = agent.config

    res.send(`Hello, ${config.label}!`)
  })

  const { start } = await setupApp({
    baseApp: app,
    adminPort: 5001,
    enableCors: true,

    agent,
  })

  start()
}

run()
