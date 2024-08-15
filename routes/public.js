import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

// Cadastro
router.post("/cadastro", async (req, res) => {
	try {
		const user = req.body;

		const salt = await bcrypt.genSalt(10);
		const hashPassworld = await bcrypt.hash(user.password, salt);

		const userDB = await prisma.user.create({
			data: {
				email: user.email,
				name: user.name,
				password: hashPassworld,
			},
		});

		res.status(201).json(userDB);
	} catch (err) {
		res.status(500).json({ message: "Erro no Servidor, tente novamente" });
	}
});

router.post("/login", async (req, res) => {
	try {
		const userInfo = req.body;

		//Busca o usuario no banco de dados
		const user = await prisma.user.findUnique({
			where: { email: userInfo.email },
		});

		//Verifica se o usuario existe dentro do banco
		if (!user) {
			return res.status(404).json({ message: "Usuario nao encontrado!" });
		}

		// Comparar a senha do banco com a que o usuario digitou
		const isMatch = await bcrypt.compare(userInfo.password, user.password);

		if (!isMatch) {
			return res.status(400).json({ message: "senha invalida" });
		}

		//Gerar token JWT
		const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "5m" });

		res.status(200).json(token);
	} catch (err) {
		res.status(500).json({ message: "Erro no Servidor, tente novamente" });
	}
});

export default router;
