import express, {Request, Response, NextFunction} from "express";
import session from "express-session";
import { readFileSync, writeFileSync } from "fs";
import bcrypt from "bcrypt"
import { middlewareValidar } from "./middlewares/validators";
import { limiterGeral, limiterLogin } from "./middlewares/rate-limiter";
import cors from "cors"
import helmet from "helmet";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(limiterGeral)
app.use(cors())
app.use(helmet())

app.use(session({ secret: "123-senha-secreta-senac-2026", resave: false, saveUninitialized: false,
  cookie: { maxAge: 60*60*1000, httpOnly: true, secure: false } }));
                        

app.set("view engine", "ejs");
app.set("views", "./src/views");
app.use(express.static("public"));

function carregarUsers() { try{return JSON.parse(readFileSync("dados/usuarios.json","utf-8"));}catch{return [];} }
function salvarUsers(u:any[]) { writeFileSync("dados/usuarios.json", JSON.stringify(u,null,2)); }
function carregarComentarios() { try{return JSON.parse(readFileSync("dados/comentarios.json","utf-8"));}catch{return [];} }
function salvarComentarios(c:any[]) { writeFileSync("dados/comentarios.json", JSON.stringify(c,null,2)); }

// LOGIN
app.get("/login", (req,res) => { const flash=req.session.flash||null; req.session.flash=null; res.render("login",{flash}); });
app.post("/login", limiterLogin, (req,res) => {
  const {email,senha} = req.body;
  const users = carregarUsers();

  const user = users.find((u:any) => u.email === email);
  let erros: String[] = []

    if (!user) {res.status(400).json({erro: "Email ou senha incorretos"}); return;}

  req.session.userId = user.id; req.session.userName = user.nome; req.session.userRole = user.role;
  res.redirect("/");
});

// REGISTRO
app.get("/registro", (req,res) => { res.render("registro",{flash:null}); });
app.post("/registro", limiterLogin, (req,res) => {
  const {nome,email,senha} = req.body;
  let erros: String[] = []
  if(!nome || nome === "") {
    erros.push("O nome do usuário é obrigatório!")
  }
  if(!email || !email.includes("@")) {
    erros.push("Email inválido.")
  }
  if(senha.length < 6) {
    erros.push("A senha deve ter ao menos 6 dígitos.")
  }

  if(erros.length > 0) {
    return res.redirect("/registro");
  }

  const users = carregarUsers();

  bcrypt.hash(senha, 10)
  users.push({ id: users.length+1, nome, email, senha, role: "user" });
  salvarUsers(users);
  req.session.flash = "Conta criada!"; res.redirect("/login");
});

app.get("/logout", (req,res) => { req.session.destroy(()=>res.redirect("/login")); });

// HOME + COMENTÁRIOS
app.get("/", (req,res) => {
  if (!req.session.userId) { res.redirect("/login"); return; }
  const comentarios = carregarComentarios();
  const flash = req.session.flash||null; req.session.flash=null;
  res.render("home", { nome:req.session.userName, role:req.session.userRole, comentarios, flash });
});

app.post("/comentar", middlewareValidar, (req,res) => {
  if (!req.session.userId) { res.redirect("/login"); return; }

  const coments = carregarComentarios();
  coments.push({ id: coments.length+1, userId: req.session.userId, autor: req.session.userName,
    texto: req.body.texto, data: new Date().toLocaleDateString("pt-BR") });
  salvarComentarios(coments);
  res.redirect("/");
});

// EDITAR COMENTÁRIO
app.post("/comentarios/:id/editar", (req,res) => {
  if (!req.session.userId) { res.redirect("/login"); return; }
  const coments = carregarComentarios();
  const c = coments.find((c:any) => c.id === Number(req.params.id));

  if (coments.user.id !== req.session.userId) {
    res.status(403).send("Proibido"); return;
  }
  if (c) { c.texto = req.body.texto; salvarComentarios(coments); }
  res.redirect("/");
});

// REMOVER COMENTÁRIO
app.post("/comentarios/:id/remover", (req,res) => {
  if (!req.session.userId) { res.redirect("/login"); return; }
  let coments = carregarComentarios();
  coments = coments.filter((c:any) => c.id !== Number(req.params.id));
  if (coments.user.id !== req.session.userId) {
    res.status(403).send("Proibido"); return;
  }
  salvarComentarios(coments);
  res.redirect("/");
});

// API USUÁRIOS
app.get("/api/usuarios", (req,res) => {
  const users = carregarUsers();

  const {nome,email} = users
  res.json(users);
});

// ADMIN (sem guard!)
app.get("/admin", (req,res) => {
  if (!req.session.userId) { res.redirect("/login"); return; }
  if (req.session.userRole !== "admin") {
    res.redirect("/"); return;
  }
  res.render("admin", { usuarios: carregarUsers(), flash:null });
});

app.listen(3000, () => console.log("⚠️  App VULNERÁVEL rodando (NÃO usar em produção!)"));
