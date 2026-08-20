// 1. IMPORTANDO AS BIBLIOTECAS
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

// 2. INICIALIZANDO O SERVIDOR EXPRESS
const app = express();

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// 3. CONECTANDO AO BANCO DE DADOS
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',             // Modifique se o seu usuário MySQL for diferente
  password: 'ca140806',             // Modifique se o seu MySQL tiver senha
  database: 'projetoservicos' // Atualizado para o novo banco
});

db.connect((err) => {
  if (err) throw err;
  console.log('Conectado ao banco de dados projetoservicos com sucesso!');
});

const SECRET_KEY = 'minha_chave_secreta_super_segura_123';

// ==========================================
// ROTA 1: REGISTRO DE USUÁRIO (Cliente ou Trabalhador)
// ==========================================
app.post('/registrar', async (req, res) => {
  // Recebe os novos campos e o "tipo" ('cliente' ou 'trabalhador')
  const { usuario, email, telefone, senha, cpf, tipo } = req.body;

  // Validação simples do tipo
  if (!tipo || (tipo !== 'cliente' && tipo !== 'trabalhador')) {
    return res.status(400).json({ erro: 'Informe um tipo válido: "cliente" ou "trabalhador".' });
  }

  // Define a tabela de destino
  const tabela = tipo === 'cliente' ? 'clientes' : 'trabalhadores';

  try {
    // Gerando o Hash da senha
    const salt = await bcrypt.genSalt(10);
    const senhaCriptografada = await bcrypt.hash(senha, salt);

    // SQL dinamizado para a tabela correspondente
    const sql = `INSERT INTO ${tabela} (usuario, email, telefone, senha, cpf) VALUES (?, ?, ?, ?, ?)`;
    
    db.query(sql, [usuario, email, telefone, senhaCriptografada, cpf], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ erro: 'Usuário, e-mail, telefone ou CPF já cadastrado.' });
        }
        return res.status(500).json({ erro: 'Erro interno no banco de dados.' });
      }
      
      res.status(201).json({ mensagem: `${tipo === 'cliente' ? 'Cliente' : 'Trabalhador'} registrado com sucesso!` });
    });
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao processar a segurança da senha.' });
  }
});

// ==========================================
// ROTA 2: LOGIN E GERAÇÃO DE TOKEN
// ==========================================
app.post('/login', (req, res) => {
  // É possível fazer login usando o usuário ou email
  const { usuario, senha, tipo } = req.body;

  if (!tipo || (tipo !== 'cliente' && tipo !== 'trabalhador')) {
    return res.status(400).json({ erro: 'Informe o tipo de usuário: "cliente" ou "trabalhador".' });
  }

  const tabela = tipo === 'cliente' ? 'clientes' : 'trabalhadores';

  // Busca por nome de usuário OU e-mail
  const sql = `SELECT * FROM ${tabela} WHERE usuario = ? OR email = ?`;
  
  db.query(sql, [usuario, usuario], async (err, results) => {
    if (err) return res.status(500).json({ erro: 'Erro no servidor.' });
    
    if (results.length === 0) {
      return res.status(401).json({ erro: 'Usuário/E-mail não encontrado.' });
    }

    const usuarioDoBanco = results[0];

    // Comparando a senha com o Hash
    const senhaEhValida = await bcrypt.compare(senha, usuarioDoBanco.senha);

    if (!senhaEhValida) {
      return res.status(401).json({ erro: 'Senha incorreta.' });
    }

    // Gerando o Token JWT com ID, Usuário e Tipo
    const token = jwt.sign(
      { id: usuarioDoBanco.id, usuario: usuarioDoBanco.usuario, tipo: tipo },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({
      mensagem: 'Login realizado com sucesso',
      token: token,
      tipo: tipo
    });
  });
});

// 4. LIGANDO O SERVIDOR
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando e escutando na porta ${PORT}`);
  console.log(`Acesse: http://localhost:${PORT}`);
});