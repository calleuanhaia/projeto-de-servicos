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

function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });
  }

  jwt.verify(token, SECRET_KEY, (err, usuario) => {
    if (err) return res.status(403).json({ erro: 'Token inválido ou expirado.' });
    req.usuario = usuario;
    next();
  });
}

// ==========================================
// ROTA 3: CADASTRO DE SERVIÇO OFERECIDO (Trabalhador)
// ==========================================
app.post('/servicos-oferecidos', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'trabalhador') {
    return res.status(403).json({ erro: 'Apenas trabalhadores podem oferecer serviços.' });
  }

  const { titulo, descricao, preco } = req.body;
  const id_trabalhador = req.usuario.id;

  if (!titulo || !preco) {
    return res.status(400).json({ erro: 'Título e Preço são obrigatórios.' });
  }

  const sql = `INSERT INTO servicos_oferecidos (id_trabalhador, titulo, descricao, preco) VALUES (?, ?, ?, ?)`;

  db.query(sql, [id_trabalhador, titulo, descricao, preco], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ erro: 'Erro ao cadastrar serviço no banco de dados.' });
    }

    res.status(201).json({
      mensagem: 'Serviço cadastrado com sucesso!',
      id_servico: result.insertId
    });
  });
});

// ==========================================
// ROTA 4: LISTAR SERVIÇOS COM MÉDIA DE NOTAS E TELEFONE
// ==========================================
app.get('/servicos-oferecidos', autenticarToken, (req, res) => {
  const sql = `
    SELECT 
      so.id, 
      so.id_trabalhador, 
      so.titulo, 
      so.descricao, 
      so.preco, 
      so.data_criacao,
      t.usuario AS nome_trabalhador,
      t.email AS email_trabalhador,
      t.telefone AS telefone_trabalhador,
      AVG(a.nota) AS media_nota
    FROM servicos_oferecidos so
    INNER JOIN trabalhadores t ON so.id_trabalhador = t.id
    LEFT JOIN avaliacoes_servicos a ON a.id_servico = so.id
    GROUP BY so.id
    ORDER BY so.id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ erro: 'Erro ao carregar o feed de serviços.' });
    }
    res.json(results);
  });
});

// ==========================================
// ROTA 5: OBTER DETALHES DO SERVIÇO E COMENTÁRIOS
// ==========================================
app.get('/servicos-oferecidos/:id', autenticarToken, (req, res) => {
  const idServico = req.params.id;
  const idUsuario = req.usuario.id;

  const sqlServico = `
    SELECT 
      so.id, 
      so.id_trabalhador, 
      so.titulo, 
      so.descricao, 
      so.preco,
      t.usuario AS nome_trabalhador,
      t.telefone AS telefone_trabalhador
    FROM servicos_oferecidos so
    INNER JOIN trabalhadores t ON so.id_trabalhador = t.id
    WHERE so.id = ?
  `;

  const sqlComentarios = `
    SELECT 
      a.id_cliente, a.nota, a.comentario, a.data_avaliacao,
      c.usuario AS nome_cliente
    FROM avaliacoes_servicos a
    INNER JOIN clientes c ON a.id_cliente = c.id
    WHERE a.id_servico = ?
    ORDER BY a.id DESC
  `;

  db.query(sqlServico, [idServico], (err, resultsServico) => {
    if (err || resultsServico.length === 0) {
      return res.status(404).json({ erro: 'Serviço não encontrado.' });
    }

    db.query(sqlComentarios, [idServico], (errCom, resultsComentarios) => {
      if (errCom) {
        return res.status(500).json({ erro: 'Erro ao buscar comentários.' });
      }

      const jaAvaliou = req.usuario.tipo === 'cliente' && 
        resultsComentarios.some(c => c.id_cliente === idUsuario);

      res.json({
        ...resultsServico[0],
        comentarios: resultsComentarios,
        jaAvaliou: jaAvaliou
      });
    });
  });
});

// ==========================================
// ROTA 6: ADICIONAR AVALIAÇÃO (TRAVA DE UMA AVALIAÇÃO POR CLIENTE)
// ==========================================
app.post('/servicos-oferecidos/:id/avaliar', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'cliente') {
    return res.status(403).json({ erro: 'Apenas clientes podem avaliar serviços.' });
  }

  const idServico = req.params.id;
  const idCliente = req.usuario.id;
  const { nota, comentario } = req.body;

  if (!nota || nota < 1 || nota > 5) {
    return res.status(400).json({ erro: 'Forneça uma nota válida de 1 a 5.' });
  }

  // Trava no backend: verifica se o cliente já avaliou esse serviço anteriormente
  const sqlCheck = `SELECT id FROM avaliacoes_servicos WHERE id_servico = ? AND id_cliente = ?`;

  db.query(sqlCheck, [idServico, idCliente], (errCheck, resultsCheck) => {
    if (errCheck) {
      return res.status(500).json({ erro: 'Erro ao validar avaliação.' });
    }

    if (resultsCheck.length > 0) {
      return res.status(400).json({ erro: 'Você já enviou uma avaliação para este serviço.' });
    }

    const sqlInsert = `INSERT INTO avaliacoes_servicos (id_servico, id_cliente, nota, comentario) VALUES (?, ?, ?, ?)`;

    db.query(sqlInsert, [idServico, idCliente, nota, comentario || ''], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ erro: 'Erro ao salvar avaliação.' });
      }

      res.status(201).json({ mensagem: 'Avaliação enviada com sucesso!' });
    });
  });
});

// ==========================================
// ROTA: NOTIFICAÇÕES (AMBOS OS PERFIS)
// ==========================================
app.get('/notificacoes', autenticarToken, (req, res) => {
  // Retorna lista vazia caso a tabela ainda não esteja populada
  const sql = `
    SELECT id, titulo, mensagem, DATE_FORMAT(data_criacao, '%d/%m %H:%i') as data_formatada 
    FROM notificacoes 
    WHERE id_usuario = ? AND tipo_usuario = ? 
    ORDER BY id DESC LIMIT 10
  `;

  db.query(sql, [req.usuario.id, req.usuario.tipo], (err, results) => {
    if (err) {
      // Se a tabela ainda não existe no MySQL, retorna array vazio sem quebrar a tela
      return res.json([]);
    }
    res.json(results);
  });
});

// ==========================================
// ROTA: RECENTES DO TRABALHADOR
// ==========================================
app.get('/trabalhador/recentes', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'trabalhador') {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }

  const idTrabalhador = req.usuario.id;

  const sql = `
    SELECT 
      so.id, 
      so.titulo, 
      so.preco,
      'ativo' as status,
      'Sem solicitações' as nome_cliente
    FROM servicos_oferecidos so
    WHERE so.id_trabalhador = ?
    ORDER BY so.id DESC LIMIT 5
  `;

  db.query(sql, [idTrabalhador], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ erro: 'Erro ao buscar dados recentes.' });
    }
    res.json(results);
  });
});

// ==========================================
// ROTAS DE GERENCIAMENTO DE SERVIÇOS DO TRABALHADOR
// ==========================================

// 1. Buscar todos os serviços oferecidos pelo trabalhador logado
app.get('/meus-servicos-oferecidos', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'trabalhador') {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }
  
  const idTrabalhador = req.usuario.id; 
  
  const sql = 'SELECT * FROM servicos_oferecidos WHERE id_trabalhador = ? ORDER BY id DESC';
  db.query(sql, [idTrabalhador], (err, results) => {
    if (err) return res.status(500).json({ erro: 'Erro ao buscar seus serviços.' });
    res.json(results);
  });
});

// 2. Atualizar (Editar) Serviço Oferecido
app.put('/servicos-oferecidos/:id', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'trabalhador') {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }

  const { id } = req.params;
  const { titulo, descricao, preco } = req.body;
  const idTrabalhador = req.usuario.id; // Pega do Token (Segurança extra)

  if (!titulo || !preco) {
    return res.status(400).json({ erro: 'Título e Preço são obrigatórios.' });
  }

  // O 'AND id_trabalhador = ?' garante que ele não edite o serviço de outra pessoa
  const sql = 'UPDATE servicos_oferecidos SET titulo = ?, descricao = ?, preco = ? WHERE id = ? AND id_trabalhador = ?';
  db.query(sql, [titulo, descricao, preco, id, idTrabalhador], (err, result) => {
    if (err) return res.status(500).json({ erro: 'Erro ao atualizar no banco de dados.' });
    if (result.affectedRows === 0) return res.status(404).json({ erro: 'Serviço não encontrado ou acesso negado.' });
    
    res.json({ mensagem: 'Serviço atualizado com sucesso!' });
  });
});

// 3. Excluir Serviço Oferecido
app.delete('/servicos-oferecidos/:id', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'trabalhador') {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }

  const { id } = req.params;
  const idTrabalhador = req.usuario.id; // Pega do Token

  // O 'AND id_trabalhador = ?' garante que ele não apague o serviço de outra pessoa
  const sql = 'DELETE FROM servicos_oferecidos WHERE id = ? AND id_trabalhador = ?';
  db.query(sql, [id, idTrabalhador], (err, result) => {
    if (err) return res.status(500).json({ erro: 'Erro ao excluir registro.' });
    if (result.affectedRows === 0) return res.status(404).json({ erro: 'Serviço não encontrado ou acesso negado.' });
    
    res.json({ mensagem: 'Serviço deletado com sucesso!' });
  });
});

// ==========================================
// ROTA: CANCELAR UM SERVIÇO SOLICITADO (servicos)
// ==========================================
app.put('/servicos/:id/cancelar', autenticarToken, (req, res) => {
  const idServico = req.params.id;
  const idUsuario = req.usuario.id;
  const tipoUsuario = req.usuario.tipo; // 'cliente' ou 'trabalhador'
  const { motivo } = req.body;

  // Define qual coluna verificar dependendo de quem está cancelando
  const colunaFiltro = tipoUsuario === 'cliente' ? 'id_cliente' : 'id_trabalhador';
  
  // 1. Verifica se o serviço existe e pertence ao usuário logado
  const sqlCheck = `SELECT status FROM servicos WHERE id = ? AND ${colunaFiltro} = ?`;
  
  db.query(sqlCheck, [idServico, idUsuario], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ erro: 'Erro ao buscar o serviço.' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ erro: 'Serviço não encontrado ou você não tem permissão para cancelá-lo.' });
    }
    
    const statusAtual = results[0].status;

    // Se já estiver cancelado ou finalizado, bloqueia a ação
    if (statusAtual === 'CANCELADO' || statusAtual === 'CONCLUÍDO' || statusAtual === 'FINALIZADO') {
      return res.status(400).json({ erro: `Não é possível cancelar um serviço que já está ${statusAtual}.` });
    }

    // 2. Executa o cancelamento
    const sqlUpdate = `
      UPDATE servicos 
      SET status = 'CANCELADO', motivo_cancelamento = ?, cancelado_por = ? 
      WHERE id = ?
    `;
    
    db.query(sqlUpdate, [motivo || 'Motivo não informado', tipoUsuario, idServico], (errUpdate, result) => {
      if (errUpdate) {
        console.error(errUpdate);
        return res.status(500).json({ erro: 'Erro ao registrar o cancelamento.' });
      }
      
      res.json({ 
        mensagem: 'Serviço cancelado com sucesso!',
        cancelado_por: tipoUsuario,
        motivo: motivo || 'Motivo não informado'
      });
    });
  });
});

// ==========================================
// ROTA: CONTRATAR UM SERVIÇO (Cliente cria um pedido na tabela 'servicos')
// ==========================================
app.post('/servicos/contratar', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'cliente') {
    return res.status(403).json({ erro: 'Apenas clientes podem contratar serviços.' });
  }

  const { id_servico_oferecido, descricao } = req.body;
  const id_cliente = req.usuario.id;

  // Busca os dados do anúncio no catálogo para obter id_trabalhador e preco
  const sqlBuscaAnuncio = `SELECT id_trabalhador, preco, titulo FROM servicos_oferecidos WHERE id = ?`;

  db.query(sqlBuscaAnuncio, [id_servico_oferecido], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ erro: 'Serviço oferecido não encontrado no catálogo.' });
    }

    const { id_trabalhador, preco, titulo } = results[0];
    const descricaoFinal = descricao || titulo;

    const sqlInsert = `
      INSERT INTO servicos (id_cliente, id_trabalhador, descricao, valor, data_pedido, status) 
      VALUES (?, ?, ?, ?, CURDATE(), 'AGUARDANDO APROVAÇÃO')
    `;

    db.query(sqlInsert, [id_cliente, id_trabalhador, descricaoFinal, preco], (errInsert, result) => {
      if (errInsert) {
        console.error(errInsert);
        return res.status(500).json({ erro: 'Erro ao registrar contratação do serviço.' });
      }

      res.status(201).json({
        mensagem: 'Serviço contratado com sucesso!',
        id_contratacao: result.insertId
      });
    });
  });
});

// ==========================================
// ROTA: LISTAR SERVIÇOS CONTRATADOS (CLIENTE E TRABALHADOR)
// ==========================================
const buscarServicosContratados = (req, res) => {
  const idUsuario = req.usuario.id;
  const tipoUsuario = req.usuario.tipo;
  const colunaFiltro = tipoUsuario === 'cliente' ? 's.id_cliente' : 's.id_trabalhador';

  const sql = `
    SELECT 
      s.id,
      s.descricao AS titulo,
      s.descricao,
      s.valor,
      s.valor AS preco,
      s.data_pedido,
      s.data_finalizado,
      s.status,
      s.motivo_cancelamento,
      s.cancelado_por,
      c.usuario AS nome_cliente,
      t.usuario AS nome_trabalhador
    FROM servicos s
    INNER JOIN clientes c ON s.id_cliente = c.id
    INNER JOIN trabalhadores t ON s.id_trabalhador = t.id
    WHERE ${colunaFiltro} = ?
    ORDER BY s.id DESC
  `;

  db.query(sql, [idUsuario], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ erro: 'Erro ao buscar histórico de serviços contratados.' });
    }
    res.json(results);
  });
};

// Aliases para garantir compatibilidade com qualquer requisição do front-end
app.get('/servicos/contratados', autenticarToken, buscarServicosContratados);
app.get('/meus-pedidos', autenticarToken, buscarServicosContratados);
app.get('/meus-servicos-contratados', autenticarToken, buscarServicosContratados);

// ==========================================
// ROTA: ATUALIZAR STATUS DO SERVIÇO (CONCLUÍDO / CANCELADO)
// ==========================================
app.put('/servicos/:id/status', autenticarToken, (req, res) => {
  const { id } = req.params;
  const { status, motivo_cancelamento } = req.body;
  const tipoUsuario = req.usuario ? req.usuario.tipo : 'desconhecido';

  if (!status) {
    return res.status(400).json({ erro: 'O novo status é obrigatório.' });
  }

  const statusUpper = String(status).toUpperCase();
  const ehConcluido = statusUpper.includes('CONCLU');
  const ehCancelado = statusUpper.includes('CANCEL');

  // Validação obrigatória do motivo em caso de cancelamento
  if (ehCancelado && (!motivo_cancelamento || !motivo_cancelamento.trim())) {
    return res.status(400).json({ erro: 'Por favor, informe o motivo do cancelamento.' });
  }

  // Define data_finalizado como NOW() para CONCLUÍDO e CANCELADO, ou NULL para outros status
  const sql = `
    UPDATE servicos 
    SET status = ?, 
        data_finalizado = ${ (ehConcluido || ehCancelado) ? 'NOW()' : 'NULL' },
        motivo_cancelamento = ?,
        cancelado_por = ?
    WHERE id = ?
  `;

  const motivo = ehCancelado ? motivo_cancelamento.trim() : null;
  const cancelador = ehCancelado ? tipoUsuario : null;

  db.query(sql, [status, motivo, cancelador, id], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ erro: 'Erro ao atualizar status no banco de dados.' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ erro: 'Serviço não encontrado.' });
    }

    res.json({ 
      mensagem: 'Status atualizado com sucesso!',
      status: status,
      data_finalizado: (ehConcluido || ehCancelado) ? new Date() : null,
      motivo_cancelamento: motivo,
      cancelado_por: cancelador
    });
  });
});

// ==========================================
// ROTA: CONTRATAÇÃO DIRETA (COMPATÍVEL COM O FORMULÁRIO DO MODAL)
// ==========================================
app.post('/servicos', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'cliente') {
    return res.status(403).json({ erro: 'Apenas clientes podem contratar serviços.' });
  }

  const { id_trabalhador, descricao, valor, especificacoes } = req.body;
  const id_cliente = req.usuario.id;

  if (!id_trabalhador || !valor) {
    return res.status(400).json({ erro: 'ID do profissional e valor são obrigatórios.' });
  }

  // Junta a descrição original com as especificações informadas pelo cliente
  const descricaoFinal = especificacoes 
    ? `${descricao || ''}\n\n[Especificações do Cliente]: ${especificacoes}`
    : descricao;

  const sqlInsert = `
    INSERT INTO servicos (id_cliente, id_trabalhador, descricao, valor, data_pedido, status) 
    VALUES (?, ?, ?, ?, CURDATE(), 'AGUARDANDO APROVAÇÃO')
  `;

  db.query(sqlInsert, [id_cliente, id_trabalhador, descricaoFinal, valor], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ erro: 'Erro ao registrar contratação no banco de dados.' });
    }

    res.status(201).json({
      mensagem: 'Serviço contratado com sucesso!',
      id_contratacao: result.insertId
    });
  });
});

// ==========================================
// ROTA: EDITAR ANÚNCIO DO CATÁLOGO (Mantido limpo sem mexer em status)
// ==========================================
app.put('/servicos-oferecidos/:id', autenticarToken, (req, res) => {
  if (req.usuario.tipo !== 'trabalhador') {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }

  const { id } = req.params;
  const { titulo, descricao, preco } = req.body;
  const idTrabalhador = req.usuario.id;

  if (!titulo || !preco) {
    return res.status(400).json({ erro: 'Título e Preço são obrigatórios.' });
  }

  const sql = 'UPDATE servicos_oferecidos SET titulo = ?, descricao = ?, preco = ? WHERE id = ? AND id_trabalhador = ?';
  db.query(sql, [titulo, descricao, preco, id, idTrabalhador], (err, result) => {
    if (err) return res.status(500).json({ erro: 'Erro ao atualizar no banco de dados.' });
    if (result.affectedRows === 0) return res.status(404).json({ erro: 'Serviço não encontrado ou acesso negado.' });
    
    res.json({ mensagem: 'Anúncio atualizado com sucesso!' });
  });
});

const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');

// 1. Inicializa o cliente do WhatsApp (salva a sessão localmente para não precisar escanear sempre)
const client = new Client({
  authStrategy: new LocalAuth()
});

// 2. Exibe o QR Code no terminal para você conectar seu WhatsApp
client.on('qr', (qr) => {
  console.log('\n--- ESCANEIE O QR CODE COM SEU WHATSAPP ---');
  qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
  console.log('🤖 Bot do WhatsApp conectado e pronto para uso!');
});

// 3. Lógica para escutar e responder mensagens
client.on('message', async (msg) => {
  const mensagemRecebida = msg.body.toLowerCase().trim();

  // Verifica se a mensagem contém intenção de busca
  if (mensagemRecebida.includes('contratar') || mensagemRecebida.includes('encanador') || mensagemRecebida.includes('pintor')) {
    
    // Resposta imediata antes da busca
    await msg.reply('🔎 Aguarde, procurando os profissionais mais próximos...');

    // Identifica o termo digitado (ex: "encanador", "pintor")
    let termoBusca = 'encanador'; // Padrão
    if (mensagemRecebida.includes('pintor')) termoBusca = 'pintor';
    if (mensagemRecebida.includes('limpeza')) termoBusca = 'limpeza';

    // Consulta os serviços cadastrados na sua tabela 'servicos_oferecidos'
    const sql = `
      SELECT 
        so.titulo, 
        so.descricao, 
        so.preco, 
        t.usuario AS nome_trabalhador, 
        t.telefone AS telefone_trabalhador
      FROM servicos_oferecidos so
      INNER JOIN trabalhadores t ON so.id_trabalhador = t.id
      WHERE LOWER(so.titulo) LIKE ? OR LOWER(so.descricao) LIKE ?
      LIMIT 5
    `;

    const busca = `%${termoBusca}%`;

    db.query(sql, [busca, busca], (err, results) => {
      if (err || results.length === 0) {
        return msg.reply(` Desculpe, não encontrei nenhum profissional cadastrado para "${termoBusca}" no momento.`);
      }

      // Monta a resposta formatada para o WhatsApp
      let resposta = `📍 *Aqui estão os profissionais disponíveis para ${termoBusca.toUpperCase()}:*\n\n`;

      results.forEach((servico, index) => {
        resposta += `*${index + 1}. ${servico.titulo}*\n`;
        resposta += `👤 *Profissional:* ${servico.nome_trabalhador}\n`;
        resposta += `💰 *Valor:* R$ ${parseFloat(servico.preco).toFixed(2)}\n`;
        if (servico.telefone_trabalhador) {
          resposta += `📞 *Contato Direto:* wa.me/55${servico.telefone_trabalhador.replace(/\D/g, '')}\n`;
        }
        resposta += `------------------------------\n`;
      });

      resposta += `\nCaso queira mais opções ou detalhes, acesse também nosso site!`;

      // Envia a lista formatada no chat do WhatsApp
      msg.reply(resposta);
    });
  }
});

// Inicializa o Bot junto com o servidor Express
client.initialize();

// 4. LIGANDO O SERVIDOR
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando e escutando na porta ${PORT}`);
  console.log(`Acesse: http://localhost:${PORT}`);
});