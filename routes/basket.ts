/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const user = security.authenticatedUsers.from(req)

      if (!user) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }

      const basket = await BasketModel.findOne({
        where: { id, UserId: user.data.id },
        include: [{ model: ProductModel, paranoid: false, as: 'Products' }]
      })

      if (!basket) {
        res.status(404).json({ error: 'Basket not found' })
        return
      }

      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        const isValidId = id && id !== 'undefined' && id !== 'null' && id !== 'NaN'
        return isValidId && user.bid && user.bid !== parseInt(id, 10)
      })

      if (basket.Products && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
