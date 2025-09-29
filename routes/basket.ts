/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
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
     const id = parseInt(req.params.id, 10)
     const userId = (req.user as any).data.id  // récupère l'ID de l'utilisateur connecté


     const basket = await BasketModel.findOne({
       where: { id, UserId: userId }, // 🔒 sécurisation ici
       include: [{ model: ProductModel, paranoid: false, as: 'Products' }]
     })

     if (!basket) {
       return res.status(403).json({ error: 'Not your basket!' })
     }


     if (basket && Array.isArray(basket.Products) && basket.Products.length > 0) {
  basket.Products.forEach((product: any) => {
    product.name = req.__(product.name)
  })
}


     res.json(utils.queryResultToJson(basket))
   } catch (error) {
     next(error)
   }
 }
}
