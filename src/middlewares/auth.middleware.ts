import { type NextFunction, type Request, type Response } from "express";
import { decodeAccessToken } from "../services/jwt.service";
import createHttpError from "http-errors";

export function requireLogin(req: Request, res: Response, next: NextFunction) {
  const { authorization } = req.headers;

  if (authorization === undefined) {
    throw new createHttpError.Unauthorized("Token não informado");
  }

  if (!authorization.startsWith("Bearer ")) {
    throw new createHttpError.Unauthorized("Token inválido");
  }

  const token = authorization.substring("Bearer ".length);

  const { userId } = decodeAccessToken(token);

  req.userId = userId;

  return next();
}
