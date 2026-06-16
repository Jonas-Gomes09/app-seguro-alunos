import rateLimit from "express-rate-limit";

export const limiterGeral = rateLimit({
    windowMs: 15 * 60 * 1000, max: 100,
    message: {erro: "Muitas requisições, tente novamente em 15 minutos."}
})

export const limiterLogin = rateLimit({
    windowMs: 10 * 60 * 1000, max: 5,
    message: {erro: "Muitas tentativas, tente novamente em 5 minutos."}  
})