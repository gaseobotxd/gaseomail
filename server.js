const express = require('express');
const cors = require('cors');
const Imap = require('imap');
const { simpleParser } = require('mailparser');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const session = require('express-session');

const app = express();
const PORT = 3000;

// Configuração de upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/user-files', express.static('user-files'));

// Sessions
app.use(session({
    secret: 'email-client-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Configuração do servidor
function getServerConfig(email) {
    return {
        imap: {
            host: 'mail.gaseo.com.br',
            port: 993,
            tls: true,
            tlsOptions: { 
                rejectUnauthorized: false 
            },
            authTimeout: 30000,
            connTimeout: 30000,
            keepalive: true
        },
        smtp: {
            host: 'mail.gaseo.com.br',
            port: 465,
            secure: true,
            auth: {
                user: email,
                pass: '' // Será preenchido com a senha da sessão
            },
            tls: {
                rejectUnauthorized: false
            },
            connectionTimeout: 30000,
            greetingTimeout: 30000,
            socketTimeout: 30000
        }
    };
}

// Middleware de autenticação
function requireAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'Não autenticado' });
    }
}

// Função para criar conexão IMAP
function createImapConnection(config, email, password) {
    return new Imap({
        ...config.imap,
        user: email,
        password: password
    });
}

// ✅ FUNÇÃO CORRIGIDA: Adicionar prefixo INBOX aos nomes das pastas
function getFolderPath(folderName) {
    const folderMap = {
        'INBOX': 'INBOX',
        'Sent': 'INBOX.Sent',
        'Drafts': 'INBOX.Drafts', 
        'Trash': 'INBOX.Trash',
        'Starred': 'INBOX'
    };
    return folderMap[folderName] || `INBOX.${folderName}`;
}

// SISTEMA DE ARQUIVOS POR USUÁRIO
function getUserFileStructure(email) {
    const userFolder = email.split('@')[0];
    const basePath = path.join(__dirname, 'user-files', userFolder);
    
    const structure = {
        basePath: basePath,
        attachments: {
            received: path.join(basePath, 'anexos-recebidos'),
            sent: path.join(basePath, 'anexos-enviados'),
            temp: path.join(basePath, 'temp')
        }
    };

    // Criar estrutura de pastas se não existir
    Object.values(structure.attachments).forEach(folder => {
        if (!fs.existsSync(folder)) {
            fs.mkdirSync(folder, { recursive: true });
        }
    });

    return structure;
}

// Função para salvar anexo recebido
async function saveReceivedAttachment(email, attachment, emailId) {
    try {
        const userStructure = getUserFileStructure(email);
        const attachmentsFolder = userStructure.attachments.received;
        
        // Criar pasta específica para o email
        const emailFolder = path.join(attachmentsFolder, `email-${emailId}`);
        if (!fs.existsSync(emailFolder)) {
            fs.mkdirSync(emailFolder, { recursive: true });
        }

        // Gerar nome único para o arquivo
        const timestamp = Date.now();
        const safeFilename = attachment.filename 
            ? attachment.filename.replace(/[^a-zA-Z0-9.-]/g, '_')
            : `anexo-${timestamp}.dat`;
        
        const filePath = path.join(emailFolder, safeFilename);
        
        // Salvar o conteúdo do anexo
        if (attachment.content) {
            fs.writeFileSync(filePath, attachment.content);
        }

        return {
            savedPath: path.relative(userStructure.basePath, filePath),
            filename: safeFilename,
            originalName: attachment.filename,
            size: attachment.size,
            contentType: attachment.contentType,
            emailId: emailId,
            savedAt: new Date().toISOString()
        };
    } catch (error) {
        console.error('❌ Erro ao salvar anexo:', error);
        return null;
    }
}

// ROTA PARA BAIXAR ARQUIVOS SALVOS
app.get('/api/download-saved-attachment/:filename', requireAuth, (req, res) => {
    const { filename } = req.params;
    const { email } = req.session.user;
    
    try {
        const userStructure = getUserFileStructure(email);
        const filePath = path.join(userStructure.basePath, filename);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Arquivo não encontrado' });
        }

        const stat = fs.statSync(filePath);
        const originalName = path.basename(filePath);
        
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${originalName}"`);
        res.setHeader('Content-Length', stat.size);
        
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);
        
    } catch (error) {
        console.error('❌ Erro ao baixar arquivo salvo:', error);
        res.status(500).json({ error: 'Erro ao baixar arquivo' });
    }
});

// ROTA PARA LISTAR ARQUIVOS DO USUÁRIO
app.get('/api/user-files', requireAuth, (req, res) => {
    const { email } = req.session.user;
    
    try {
        const userStructure = getUserFileStructure(email);
        const files = [];

        function scanFolder(folderPath, category) {
            if (fs.existsSync(folderPath)) {
                const items = fs.readdirSync(folderPath, { withFileTypes: true });
                
                items.forEach(item => {
                    const fullPath = path.join(folderPath, item.name);
                    const relativePath = path.relative(userStructure.basePath, fullPath);
                    
                    if (item.isDirectory()) {
                        scanFolder(fullPath, category);
                    } else {
                        const stat = fs.statSync(fullPath);
                        files.push({
                            name: item.name,
                            path: relativePath,
                            fullPath: fullPath,
                            size: stat.size,
                            modified: stat.mtime,
                            category: category,
                            type: path.extname(item.name).toLowerCase() || 'arquivo'
                        });
                    }
                });
            }
        }

        // Escanear pastas de anexos
        Object.entries(userStructure.attachments).forEach(([type, folderPath]) => {
            scanFolder(folderPath, `anexos-${type}`);
        });

        files.sort((a, b) => new Date(b.modified) - new Date(a.modified));

        res.json({ 
            success: true, 
            files: files,
            total: files.length,
            user: email,
            structure: {
                base: path.basename(userStructure.basePath),
                totalSize: files.reduce((sum, file) => sum + file.size, 0)
            }
        });

    } catch (error) {
        console.error('❌ Erro ao listar arquivos:', error);
        res.status(500).json({ error: 'Erro ao listar arquivos' });
    }
});

// ROTA PARA EXCLUIR ARQUIVO
app.delete('/api/user-files/:filename', requireAuth, (req, res) => {
    const { filename } = req.params;
    const { email } = req.session.user;
    
    try {
        const userStructure = getUserFileStructure(email);
        const filePath = path.join(userStructure.basePath, filename);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Arquivo não encontrado' });
        }

        fs.unlinkSync(filePath);
        
        // Verificar se a pasta ficou vazia e remover também
        const folderPath = path.dirname(filePath);
        if (fs.existsSync(folderPath)) {
            const filesInFolder = fs.readdirSync(folderPath);
            if (filesInFolder.length === 0) {
                fs.rmdirSync(folderPath);
            }
        }

        res.json({ 
            success: true, 
            message: 'Arquivo excluído com sucesso' 
        });

    } catch (error) {
        console.error('❌ Erro ao excluir arquivo:', error);
        res.status(500).json({ error: 'Erro ao excluir arquivo' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password, rememberMe } = req.body;
    
    console.log('🔐 Tentando login:', email);
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    const config = getServerConfig(email);
    const imap = createImapConnection(config, email, password);

    const connectionTimeout = setTimeout(() => {
        imap.end();
        res.status(408).json({ error: 'Timeout de conexão' });
    }, 30000);

    imap.once('ready', () => {
        clearTimeout(connectionTimeout);
        console.log('✅ Login bem-sucedido:', email);
        imap.end();
        
        req.session.user = {
            email: email,
            password: password,
            loginTime: new Date()
        };
        
        if (rememberMe) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
        }

        res.json({ 
            success: true, 
            message: 'Login realizado com sucesso',
            user: email 
        });
    });

    imap.once('error', (err) => {
        clearTimeout(connectionTimeout);
        console.error('❌ Erro de login:', err);
        res.status(401).json({ 
            error: 'Falha na autenticação. Verifique email/senha.' 
        });
    });

    imap.connect();
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Logout realizado' });
});

// Verificar sessão
app.get('/api/session', (req, res) => {
    if (req.session.user) {
        res.json({ 
            authenticated: true, 
            user: req.session.user.email,
            loginTime: req.session.user.loginTime
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Buscar emails
app.post('/api/emails', requireAuth, async (req, res) => {
    const { folder = 'INBOX', limit = 50 } = req.body;
    const { email, password } = req.session.user;

    console.log(`📧 Buscando emails na caixa: ${folder}`);

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        const emails = await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                reject(new Error('Timeout ao buscar emails'));
            }, 45000);

            let emailList = [];

            imap.once('ready', () => {
                const actualFolder = getFolderPath(folder);

                imap.openBox(actualFolder, true, (err, box) => {
                    if (err) {
                        clearTimeout(timeout);
                        imap.end();
                        console.error('❌ Erro ao abrir caixa:', err);
                        return resolve([]);
                    }

                    const totalMessages = box.messages.total;
                    console.log(`📦 Total de mensagens em ${actualFolder}: ${totalMessages}`);

                    if (totalMessages === 0) {
                        clearTimeout(timeout);
                        imap.end();
                        return resolve([]);
                    }

                    const start = Math.max(1, totalMessages - limit + 1);
                    const end = totalMessages;
                    const range = `${start}:${end}`;

                    const fetch = imap.seq.fetch(range, {
                        bodies: ['HEADER.FIELDS (FROM TO SUBJECT DATE)'],
                        struct: true
                    });

                    fetch.on('message', (msg, seqno) => {
                        let emailData = {
                            id: seqno,
                            uid: null,
                            from: '',
                            to: '',
                            subject: '',
                            date: '',
                            preview: '',
                            read: true,
                            hasAttachments: false,
                            folder: folder,
                            flags: []
                        };

                        msg.on('body', (stream, info) => {
                            let buffer = '';
                            stream.on('data', (chunk) => {
                                buffer += chunk.toString('utf8');
                            });
                            stream.on('end', () => {
                                try {
                                    const headers = Imap.parseHeader(buffer);
                                    emailData.from = headers.from ? headers.from[0] : 'Desconhecido';
                                    emailData.to = headers.to ? headers.to[0] : '';
                                    emailData.subject = headers.subject ? headers.subject[0] : '(Sem assunto)';
                                    emailData.date = headers.date ? headers.date[0] : new Date().toISOString();
                                } catch (e) {
                                    console.error('Erro ao parsear headers:', e);
                                }
                            });
                        });

                        msg.once('attributes', (attrs) => {
                            emailData.uid = attrs.uid;
                            emailData.read = !attrs.flags || !attrs.flags.includes('\\Seen');
                            emailData.flags = attrs.flags || [];
                            
                            if (attrs.struct) {
                                emailData.hasAttachments = checkForAttachments(attrs.struct);
                            }
                        });

                        msg.once('end', () => {
                            emailList.push(emailData);
                        });
                    });

                    fetch.once('error', (err) => {
                        clearTimeout(timeout);
                        imap.end();
                        console.error('❌ Erro no fetch:', err);
                        reject(err);
                    });

                    fetch.once('end', () => {
                        clearTimeout(timeout);
                        imap.end();
                        console.log(`✅ Busca concluída. Encontrados: ${emailList.length} emails`);
                        resolve(emailList.reverse());
                    });
                });
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                console.error('❌ Erro de conexão IMAP:', err);
                reject(err);
            });

            imap.connect();
        });

        res.json({ 
            emails: emails,
            total: emails.length,
            folder: folder
        });

    } catch (error) {
        console.error('❌ Erro geral ao buscar emails:', error);
        res.json({ 
            emails: [], 
            total: 0,
            folder: folder
        });
    }
});

// Buscar email completo - VERSÃO QUE SALVA ANEXOS
app.post('/api/email-complete', requireAuth, async (req, res) => {
    const { folder = 'INBOX', seqno } = req.body;
    const { email, password } = req.session.user;

    console.log(`📨 Buscando email COMPLETO ${seqno}`);

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        const emailData = await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                reject(new Error('Timeout ao buscar email'));
            }, 45000);

            imap.once('ready', () => {
                const actualFolder = getFolderPath('INBOX'); // Sempre buscar da INBOX

                imap.openBox(actualFolder, false, (err, box) => {
                    if (err) {
                        clearTimeout(timeout);
                        imap.end();
                        return reject(err);
                    }

                    const fetch = imap.seq.fetch(seqno, { 
                        bodies: [''],
                        struct: true
                    });

                    let emailBuffer = '';

                    fetch.on('message', (msg, seqno) => {
                        let attributes = {};

                        msg.once('attributes', (attrs) => {
                            attributes = attrs;
                        });

                        msg.on('body', (stream, info) => {
                            stream.on('data', (chunk) => {
                                emailBuffer += chunk.toString('utf8');
                            });

                            stream.once('end', async () => {
                                try {
                                    const parsed = await simpleParser(emailBuffer);
                                    
                                    const emailData = {
                                        id: seqno,
                                        from: parsed.from ? parsed.from.text : 'Desconhecido',
                                        to: parsed.to ? parsed.to.text : '',
                                        subject: parsed.subject || '(Sem assunto)',
                                        date: parsed.date || new Date().toISOString(),
                                        body: parsed.text || 'Nenhum conteúdo disponível',
                                        text: parsed.text || '',
                                        html: parsed.html || '',
                                        attachments: [],
                                        flags: attributes.flags || []
                                    };

                                    // SALVAR ANEXOS
                                    if (parsed.attachments && parsed.attachments.length > 0) {
                                        console.log(`📎 Encontrados ${parsed.attachments.length} anexos para salvar`);
                                        
                                        for (let attachment of parsed.attachments) {
                                            const savedAttachment = await saveReceivedAttachment(
                                                email, 
                                                attachment, 
                                                seqno
                                            );
                                            
                                            if (savedAttachment) {
                                                emailData.attachments.push(savedAttachment);
                                            }
                                        }
                                    }

                                    clearTimeout(timeout);
                                    imap.end();
                                    resolve(emailData);
                                } catch (error) {
                                    clearTimeout(timeout);
                                    imap.end();
                                    reject(error);
                                }
                            });
                        });
                    });

                    fetch.once('error', (fetchErr) => {
                        clearTimeout(timeout);
                        imap.end();
                        reject(fetchErr);
                    });
                });
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                reject(err);
            });

            imap.connect();
        });

        res.json({ email: emailData });

    } catch (error) {
        console.error('❌ Erro ao buscar email completo:', error);
        res.status(500).json({ error: 'Erro ao buscar email: ' + error.message });
    }
});

// ✅ ROTA CORRIGIDA: Enviar email e SALVAR nos Enviados
app.post('/api/send', upload.array('attachments'), requireAuth, async (req, res) => {
    const { to, subject, text } = req.body;
    const attachments = req.files || [];
    const { email, password } = req.session.user;

    console.log(`📤 Enviando email de: ${email} para: ${to}`);

    if (!to || !subject || !text) {
        return res.status(400).json({ 
            error: 'Todos os campos são obrigatórios: para, assunto, mensagem' 
        });
    }

    const config = getServerConfig(email);
    
    // Configurar transporter com a senha correta
    const transporter = nodemailer.createTransport({
        host: config.smtp.host,
        port: config.smtp.port,
        secure: config.smtp.port === 465,
        auth: {
            user: email,
            pass: password
        },
        tls: {
            rejectUnauthorized: false
        },
        connectionTimeout: 30000,
        greetingTimeout: 30000,
        socketTimeout: 30000
    });

    try {
        // Verificar conexão SMTP
        await transporter.verify();
        console.log('✅ Conexão SMTP verificada');

        const mailOptions = {
            from: `"${email.split('@')[0]}" <${email}>`,
            to: to,
            subject: subject,
            text: text,
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
                        <h2 style="color: #333; margin-bottom: 15px;">${subject}</h2>
                        <div style="line-height: 1.6; color: #333; white-space: pre-line;">
                            ${text.replace(/\n/g, '<br>')}
                        </div>
                        ${attachments.length > 0 ? `
                        <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #ddd;">
                            <strong>Anexos (${attachments.length}):</strong><br>
                            ${attachments.map(file => 
                                `<div style="color: #666; margin: 5px 0;">📎 ${file.originalname}</div>`
                            ).join('')}
                        </div>
                        ` : ''}
                    </div>
                </div>
            `,
            attachments: attachments.map(file => ({
                filename: file.originalname,
                path: file.path,
                contentType: file.mimetype
            }))
        };

        console.log('📨 Enviando email...');
        const info = await transporter.sendMail(mailOptions);
        
        // ✅ CORREÇÃO CRÍTICA: SALVAR EMAIL NA PASTA "Sent" (Enviados)
        console.log('💾 Salvando email nos Enviados...');
        try {
            await saveEmailToSentFolder(email, password, mailOptions, info.messageId);
        } catch (saveError) {
            console.warn('⚠️  Aviso: Não foi possível salvar nos Enviados, mas o email foi enviado:', saveError.message);
        }
        
        // Limpar arquivos temporários
        attachments.forEach(file => {
            if (fs.existsSync(file.path)) {
                fs.unlinkSync(file.path);
            }
        });

        console.log('✅ Email enviado com sucesso:', info.messageId);
        res.json({ 
            success: true, 
            message: 'Email enviado com sucesso!',
            messageId: info.messageId
        });

    } catch (error) {
        console.error('❌ ERRO AO ENVIAR EMAIL:', error);
        
        // Limpar arquivos temporários em caso de erro
        attachments.forEach(file => {
            if (fs.existsSync(file.path)) {
                fs.unlinkSync(file.path);
            }
        });

        let errorMessage = 'Erro ao enviar email';
        if (error.code === 'EAUTH') {
            errorMessage = 'Erro de autenticação. Verifique suas credenciais.';
        } else if (error.code === 'ECONNECTION') {
            errorMessage = 'Erro de conexão com o servidor de email.';
        } else {
            errorMessage = error.message;
        }

        res.status(500).json({ 
            error: errorMessage
        });
    }
});

// ✅ FUNÇÃO CORRIGIDA: Salvar email na pasta Sent (Enviados) com prefixo INBOX
async function saveEmailToSentFolder(email, password, mailOptions, messageId) {
    return new Promise((resolve, reject) => {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        const timeout = setTimeout(() => {
            imap.end();
            reject(new Error('Timeout ao salvar nos enviados'));
        }, 30000);

        imap.once('ready', () => {
            // ✅ CORREÇÃO: Usar o caminho correto da pasta Sent
            const sentFolder = getFolderPath('Sent');
            
            // Criar o email no formato RFC822 para salvar na pasta Sent
            const rfc822Message = `From: ${mailOptions.from}
To: ${mailOptions.to}
Subject: ${mailOptions.subject}
Date: ${new Date().toUTCString()}
Message-ID: <${messageId}>
Content-Type: text/html; charset="UTF-8"

${mailOptions.html}`;

            console.log(`💾 Tentando salvar em: ${sentFolder}`);
            
            imap.append(rfc822Message, {
                mailbox: sentFolder, // ✅ CORREÇÃO: Usar sentFolder com prefixo
                flags: ['\\Seen'] // Marcar como lido
            }, (err) => {
                clearTimeout(timeout);
                imap.end();
                
                if (err) {
                    console.error('❌ Erro ao salvar nos enviados:', err);
                    reject(err);
                } else {
                    console.log('✅ Email salvo na pasta Sent (Enviados)');
                    resolve();
                }
            });
        });

        imap.once('error', (err) => {
            clearTimeout(timeout);
            reject(err);
        });

        imap.connect();
    });
}

// ✅ ROTA CORRIGIDA: Mover para lixeira - VERSÃO MELHORADA
app.post('/api/move-to-trash', requireAuth, async (req, res) => {
    const { folder, seqno } = req.body;
    const { email, password } = req.session.user;

    console.log(`🗑️ Movendo email ${seqno} para lixeira da pasta: ${folder}`);

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                reject(new Error('Timeout ao mover email'));
            }, 30000);

            imap.once('ready', () => {
                const actualFolder = getFolderPath(folder);
                const trashFolder = getFolderPath('Trash');

                imap.openBox(actualFolder, false, (err, box) => {
                    if (err) {
                        clearTimeout(timeout);
                        imap.end();
                        return reject(err);
                    }

                    // ✅ CORREÇÃO: Usar busca por UID em vez de seqno
                    imap.search(['ALL'], (searchErr, results) => {
                        if (searchErr) {
                            clearTimeout(timeout);
                            imap.end();
                            return reject(searchErr);
                        }

                        if (!results || results.length === 0) {
                            clearTimeout(timeout);
                            imap.end();
                            return reject(new Error('Nenhum email encontrado'));
                        }

                        // Encontrar o UID correspondente ao seqno
                        const targetUid = results[seqno - 1]; // seqno é base 1
                        
                        if (!targetUid) {
                            clearTimeout(timeout);
                            imap.end();
                            return reject(new Error('Email não encontrado'));
                        }

                        console.log(`📧 Movendo email UID: ${targetUid} para ${trashFolder}`);
                        
                        imap.move(targetUid, trashFolder, (moveErr) => {
                            clearTimeout(timeout);
                            imap.end();
                            
                            if (moveErr) {
                                console.error('❌ Erro ao mover email:', moveErr);
                                return reject(moveErr);
                            }
                            
                            console.log('✅ Email movido para lixeira com sucesso');
                            resolve();
                        });
                    });
                });
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                reject(err);
            });

            imap.connect();
        });

        res.json({ success: true, message: 'Email movido para lixeira' });

    } catch (error) {
        console.error('❌ Erro ao mover para lixeira:', error);
        res.status(500).json({ error: 'Erro ao mover email para lixeira: ' + error.message });
    }
});

// ✅ ROTA CORRIGIDA: Excluir permanentemente - VERSÃO MELHORADA
app.post('/api/delete-permanently', requireAuth, async (req, res) => {
    const { seqno } = req.body;
    const { email, password } = req.session.user;

    console.log(`🔥 Excluindo permanentemente email ${seqno} da lixeira`);

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                reject(new Error('Timeout ao excluir email'));
            }, 30000);

            imap.once('ready', () => {
                const trashFolder = getFolderPath('Trash');
                
                imap.openBox(trashFolder, false, (err, box) => {
                    if (err) {
                        clearTimeout(timeout);
                        imap.end();
                        return reject(err);
                    }

                    // ✅ CORREÇÃO: Usar busca por UID em vez de seqno
                    imap.search(['ALL'], (searchErr, results) => {
                        if (searchErr) {
                            clearTimeout(timeout);
                            imap.end();
                            return reject(searchErr);
                        }

                        if (!results || results.length === 0) {
                            clearTimeout(timeout);
                            imap.end();
                            return reject(new Error('Nenhum email na lixeira'));
                        }

                        // Encontrar o UID correspondente ao seqno
                        const targetUid = results[seqno - 1]; // seqno é base 1
                        
                        if (!targetUid) {
                            clearTimeout(timeout);
                            imap.end();
                            return reject(new Error('Email não encontrado na lixeira'));
                        }

                        console.log(`🗑️ Excluindo permanentemente UID: ${targetUid}`);
                        
                        imap.addFlags(targetUid, ['\\Deleted'], (flagErr) => {
                            if (flagErr) {
                                clearTimeout(timeout);
                                imap.end();
                                return reject(flagErr);
                            }

                            imap.expunge((expungeErr) => {
                                clearTimeout(timeout);
                                imap.end();
                                
                                if (expungeErr) {
                                    return reject(expungeErr);
                                }
                                
                                console.log('✅ Email excluído permanentemente');
                                resolve();
                            });
                        });
                    });
                });
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                reject(err);
            });

            imap.connect();
        });

        res.json({ success: true, message: 'Email excluído permanentemente' });

    } catch (error) {
        console.error('❌ Erro ao excluir permanentemente:', error);
        res.status(500).json({ error: 'Erro ao excluir email permanentemente: ' + error.message });
    }
});

// ROTA: Marcar/desmarcar como importante
app.post('/api/toggle-star', requireAuth, async (req, res) => {
    const { folder, seqno, starred } = req.body;
    const { email, password } = req.session.user;

    console.log(`⭐ ${starred ? 'Marcando' : 'Desmarcando'} email ${seqno}`);

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                reject(new Error('Timeout ao marcar email'));
            }, 30000);

            imap.once('ready', () => {
                const actualFolder = getFolderPath(folder);

                imap.openBox(actualFolder, false, (err, box) => {
                    if (err) {
                        clearTimeout(timeout);
                        imap.end();
                        return reject(err);
                    }

                    // Buscar UID do email
                    const fetch = imap.seq.fetch(seqno, { bodies: '' });
                    
                    fetch.on('message', (msg, seqno) => {
                        msg.once('attributes', (attrs) => {
                            const flagAction = starred ? imap.addFlags : imap.removeFlags;
                            
                            flagAction.call(imap, attrs.uid, ['\\Flagged'], (flagErr) => {
                                clearTimeout(timeout);
                                imap.end();
                                
                                if (flagErr) {
                                    return reject(flagErr);
                                }
                                
                                console.log(`✅ Email ${starred ? 'marcado' : 'desmarcado'} como importante`);
                                resolve();
                            });
                        });
                    });

                    fetch.once('error', (fetchErr) => {
                        clearTimeout(timeout);
                        imap.end();
                        reject(fetchErr);
                    });
                });
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                reject(err);
            });

            imap.connect();
        });

        res.json({ 
            success: true, 
            message: starred ? 'Email marcado como importante' : 'Email desmarcado' 
        });

    } catch (error) {
        console.error('❌ Erro ao marcar/desmarcar email:', error);
        res.status(500).json({ error: 'Erro ao marcar/desmarcar email: ' + error.message });
    }
});

// ROTA: Salvar rascunho
app.post('/api/save-draft', requireAuth, async (req, res) => {
    const { to, subject, text } = req.body;
    const { email, password } = req.session.user;

    console.log(`💾 Salvando rascunho para: ${to}`);

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                reject(new Error('Timeout ao salvar rascunho'));
            }, 30000);

            imap.once('ready', () => {
                const draftsFolder = getFolderPath('Drafts');
                
                imap.append({
                    mailbox: draftsFolder,
                    flags: ['\\Draft'],
                    date: new Date(),
                    message: `From: ${email}\r\nTo: ${to || ''}\r\nSubject: ${subject || '(Sem assunto)'}\r\n\r\n${text || ''}`
                }, (err) => {
                    clearTimeout(timeout);
                    imap.end();
                    
                    if (err) {
                        console.error('❌ Erro ao salvar rascunho:', err);
                        return reject(err);
                    }
                    
                    console.log('✅ Rascunho salvo com sucesso');
                    resolve();
                });
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                reject(err);
            });

            imap.connect();
        });

        res.json({ 
            success: true, 
            message: 'Rascunho salvo com sucesso!' 
        });

    } catch (error) {
        console.error('❌ ERRO AO SALVAR RASCUNHO:', error);
        res.status(500).json({ 
            error: 'Erro ao salvar rascunho: ' + error.message 
        });
    }
});

// Buscar emails importantes
app.post('/api/starred-emails', requireAuth, async (req, res) => {
    const { limit = 50 } = req.body;
    const { email, password } = req.session.user;

    console.log(`⭐ Buscando emails importantes para: ${email}`);

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        const emails = await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                reject(new Error('Timeout ao buscar emails importantes'));
            }, 45000);

            let emailList = [];

            imap.once('ready', () => {
                const inboxFolder = getFolderPath('INBOX');
                
                imap.openBox(inboxFolder, false, (err, box) => {
                    if (err) {
                        clearTimeout(timeout);
                        imap.end();
                        return reject(err);
                    }

                    // Buscar emails com flag \\Flagged
                    imap.search(['FLAGGED'], (searchErr, results) => {
                        if (searchErr) {
                            clearTimeout(timeout);
                            imap.end();
                            return reject(searchErr);
                        }

                        if (!results || results.length === 0) {
                            clearTimeout(timeout);
                            imap.end();
                            return resolve([]);
                        }

                        console.log(`⭐ Encontrados ${results.length} emails importantes`);

                        // Buscar apenas os emails importantes
                        const uidsToFetch = results.slice(-limit);
                        const fetch = imap.fetch(uidsToFetch, {
                            bodies: ['HEADER.FIELDS (FROM TO SUBJECT DATE)'],
                            struct: true
                        });

                        fetch.on('message', (msg, seqno) => {
                            let emailData = {
                                id: seqno,
                                uid: null,
                                from: '',
                                to: '',
                                subject: '',
                                date: '',
                                preview: '',
                                read: true,
                                hasAttachments: false,
                                folder: 'Starred',
                                flags: []
                            };

                            msg.on('body', (stream, info) => {
                                let buffer = '';
                                stream.on('data', (chunk) => {
                                    buffer += chunk.toString('utf8');
                                });
                                stream.on('end', () => {
                                    try {
                                        const headers = Imap.parseHeader(buffer);
                                        emailData.from = headers.from ? headers.from[0] : 'Desconhecido';
                                        emailData.to = headers.to ? headers.to[0] : '';
                                        emailData.subject = headers.subject ? headers.subject[0] : '(Sem assunto)';
                                        emailData.date = headers.date ? headers.date[0] : new Date().toISOString();
                                    } catch (e) {
                                        console.error('Erro ao parsear headers:', e);
                                    }
                                });
                            });

                            msg.once('attributes', (attrs) => {
                                emailData.uid = attrs.uid;
                                emailData.flags = attrs.flags || [];
                                
                                if (attrs.struct) {
                                    emailData.hasAttachments = checkForAttachments(attrs.struct);
                                }
                                
                                emailList.push(emailData);
                            });
                        });

                        fetch.once('error', (fetchErr) => {
                            clearTimeout(timeout);
                            imap.end();
                            reject(fetchErr);
                        });

                        fetch.once('end', () => {
                            clearTimeout(timeout);
                            imap.end();
                            resolve(emailList.reverse());
                        });
                    });
                });
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                reject(err);
            });

            imap.connect();
        });

        res.json({ 
            emails: emails,
            total: emails.length
        });

    } catch (error) {
        console.error('❌ Erro ao buscar emails importantes:', error);
        res.json({ emails: [], total: 0 });
    }
});

// Buscar estatísticas
app.get('/api/stats', requireAuth, async (req, res) => {
    const { email, password } = req.session.user;
    
    console.log(`📊 Buscando estatísticas para: ${email}`);

    const stats = {
        inbox: 0,
        sent: 0,
        drafts: 0,
        trash: 0,
        starred: 0
    };

    try {
        const config = getServerConfig(email);
        const imap = createImapConnection(config, email, password);

        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                imap.end();
                resolve();
            }, 15000);

            imap.once('ready', () => {
                let boxesChecked = 0;
                const boxes = ['INBOX', 'Sent', 'Drafts', 'Trash'];

                const checkNextBox = () => {
                    if (boxesChecked >= boxes.length) {
                        clearTimeout(timeout);
                        imap.end();
                        resolve();
                        return;
                    }

                    const boxName = boxes[boxesChecked];
                    const actualFolder = getFolderPath(boxName);
                    
                    imap.openBox(actualFolder, true, (err, box) => {
                        if (!err && box) {
                            stats[boxName.toLowerCase()] = box.messages.total;
                        }
                        boxesChecked++;
                        checkNextBox();
                    });
                };

                checkNextBox();
            });

            imap.once('error', (err) => {
                clearTimeout(timeout);
                resolve();
            });

            imap.connect();
        });

        // Buscar count de emails importantes
        try {
            const config = getServerConfig(email);
            const imap2 = createImapConnection(config, email, password);

            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    imap2.end();
                    resolve();
                }, 10000);

                imap2.once('ready', () => {
                    const inboxFolder = getFolderPath('INBOX');
                    
                    imap2.openBox(inboxFolder, false, (err, box) => {
                        if (err) {
                            clearTimeout(timeout);
                            imap2.end();
                            return resolve();
                        }

                        imap2.search(['FLAGGED'], (searchErr, results) => {
                            clearTimeout(timeout);
                            imap2.end();
                            
                            if (!searchErr && results) {
                                stats.starred = results.length;
                            }
                            resolve();
                        });
                    });
                });

                imap2.once('error', (err) => {
                    clearTimeout(timeout);
                    resolve();
                });

                imap2.connect();
            });
        } catch (error) {
            console.log('⚠️  Não foi possível contar emails importantes');
        }

        console.log('📊 Estatísticas:', stats);
        res.json(stats);

    } catch (error) {
        console.error('❌ Erro ao buscar estatísticas:', error);
        res.json(stats);
    }
});

// Funções auxiliares
function extractAttachmentsInfo(struct) {
    const attachments = [];
    
    function traverse(part, path = '') {
        if (!part) return;

        const isTextPart = part.type && (
            part.type.toLowerCase().includes('text/plain') ||
            part.type.toLowerCase().includes('text/html') ||
            part.type === 'multipart/alternative' ||
            part.type === 'multipart/mixed' ||
            part.type === 'multipart/related'
        );

        const isAttachment = part.disposition && 
            (part.disposition.type.toLowerCase() === 'attachment' || 
             part.disposition.type.toLowerCase() === 'inline');

        if (isAttachment || (!isTextPart && part.disposition && part.disposition.params && part.disposition.params.filename)) {
            const filename = part.disposition && part.disposition.params ? 
                part.disposition.params.filename : 
                (part.params && part.params.name) ? part.params.name :
                `arquivo-${Date.now()}.${part.subtype || 'dat'}`;

            attachments.push({
                filename: filename,
                contentType: part.type || 'application/octet-stream',
                size: part.size || 0,
                partId: path || '1',
                encoding: part.encoding
            });
        }
        
        if (part.parts && Array.isArray(part.parts)) {
            part.parts.forEach((nestedPart, index) => {
                const newPath = path ? `${path}.${index + 1}` : `${index + 1}`;
                traverse(nestedPart, newPath);
            });
        }
    }
    
    if (Array.isArray(struct)) {
        struct.forEach(part => traverse(part));
    } else if (struct) {
        traverse(struct);
    }
    
    return attachments;
}

function checkForAttachments(struct) {
    const parts = Array.isArray(struct) ? struct : [struct];
    for (const part of parts) {
        if (part.disposition && part.disposition.type && 
            (part.disposition.type.toLowerCase() === 'attachment' || 
             part.disposition.type.toLowerCase() === 'inline')) {
            return true;
        }
        if (part.parts && checkForAttachments(part.parts)) {
            return true;
        }
    }
    return false;
}

// Servir frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor Email Pro rodando: http://localhost:${PORT}`);
    console.log(`📧 Sistema COMPLETO - Todas as funcionalidades ativas`);
    console.log(`✅ Envio de emails FUNCIONANDO com salvamento nos Enviados`);
    console.log(`🗑️  Lixeira FUNCIONANDO - Mover e excluir permanentemente`);
    console.log(`📁 Sistema de arquivos por usuário ATIVADO`);
    console.log(`🔧 Prefixo INBOX aplicado a todas as pastas`);
});