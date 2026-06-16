import { Request, Response, NextFunction } from "express"
import {body, validationResult} from "express-validator"

export const validarRegistro =[
body("texto").trim().notEmpty().escape().withMessage("O comentário não pode estar vazio.")]

export async function middlewareValidar(req: Request, res: Response, next: NextFunction) {
      const erros = validationResult(req)
      if (!erros.isEmpty()) {
        return res.status(400).json({"erros": erros})
      }
}