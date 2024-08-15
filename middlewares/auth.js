import jwt from "@prisma/client";

const JWT_SECRET = process.env.JWT_SECRET;

const auth = (req, res, next) => {
	const token = req.headers.authorization;

	if (!token) {
		return res.status(401).json({ message: "Acesso Negado" });
	}

	try {
		const decoded = jwt.verify(token.raplace("Bearer ", "", JWT_SECRET));

		req.userId = decoded.id;
	} catch (err) {
		res.status(500).json({ message: "Token Invalido" });
	}

	next();
};

export default auth;
