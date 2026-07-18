const crypto = require('crypto');
const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const multer = require('multer');

const app = express();
const port = process.env.PORT || 3000;
const rootDir = __dirname;
const dataDir = path.join(rootDir, 'data');
const postsFile = path.join(dataDir, 'posts.json');
const usersFile = path.join(dataDir, 'users.json');
const sessionCookieName = 'bg_session';
const privateAccessPassword = '8569';
const allowedCategories = ['게임', '독서', 'PPT', '컴퓨터', '일기', '발표', '일반'];
const sessions = new Map();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 8 * 1024 * 1024
  }
});

app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.sendStatus(204);
    return;
  }

  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  next();
});

app.use(express.static(rootDir));

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) {
    return cookies;
  }

  cookieHeader.split(';').forEach((part) => {
    const [name, ...valueParts] = part.trim().split('=');
    if (!name) {
      return;
    }

    cookies[name] = decodeURIComponent(valueParts.join('='));
  });

  return cookies;
}

function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const candidateHash = crypto.scryptSync(password, salt, 64).toString('hex');
  const left = Buffer.from(candidateHash, 'hex');
  const right = Buffer.from(hash, 'hex');

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function createSession(username) {
  const sessionId = crypto.randomBytes(24).toString('hex');
  sessions.set(sessionId, username);
  return sessionId;
}

function setSessionCookie(res, sessionId) {
  res.setHeader('Set-Cookie', `${sessionCookieName}=${encodeURIComponent(sessionId)}; HttpOnly; Path=/; SameSite=Lax`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${sessionCookieName}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

async function ensureDataFiles() {
  await fs.mkdir(dataDir, { recursive: true });

  try {
    await fs.access(postsFile);
  } catch {
    await fs.writeFile(postsFile, '[]\n', 'utf8');
  }

  try {
    await fs.access(usersFile);
  } catch {
    await fs.writeFile(usersFile, '[]\n', 'utf8');
  }
}

async function readJsonFile(filePath) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function saveJsonFile(filePath, items) {
  await fs.writeFile(filePath, `${JSON.stringify(items, null, 2)}\n`, 'utf8');
}

function normalizeComment(comment) {
  return {
    id: String(comment.id || crypto.randomUUID()),
    content: String(comment.content || '').trim(),
    authorName: String(comment.authorName || '').trim(),
    authorUsername: String(comment.authorUsername || '').trim(),
    createdAt: String(comment.createdAt || new Date().toISOString())
  };
}

function normalizePost(post) {
  return {
    id: String(post.id || crypto.randomUUID()),
    title: String(post.title || '').trim(),
    content: String(post.content || '').trim(),
    category: allowedCategories.includes(post.category) ? post.category : '일반',
    authorName: String(post.authorName || '').trim(),
    authorUsername: String(post.authorUsername || '').trim(),
    createdAt: String(post.createdAt || new Date().toISOString()),
    updatedAt: String(post.updatedAt || post.createdAt || new Date().toISOString()),
    image: post.image && typeof post.image === 'object' ? {
      name: String(post.image.name || ''),
      mimeType: String(post.image.mimeType || ''),
      dataUrl: String(post.image.dataUrl || '')
    } : null,
    hearts: Array.isArray(post.hearts) ? post.hearts.filter((item) => typeof item === 'string' && item.trim()) : [],
    comments: Array.isArray(post.comments) ? post.comments.map(normalizeComment).filter((comment) => comment.content) : []
  };
}

async function readUsers() {
  return readJsonFile(usersFile);
}

async function saveUsers(users) {
  await saveJsonFile(usersFile, users);
}

async function readPosts() {
  const posts = await readJsonFile(postsFile);
  return posts.map(normalizePost);
}

async function savePosts(posts) {
  await saveJsonFile(postsFile, posts);
}

function getSessionUsername(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[sessionCookieName];
  if (!sessionId) {
    return null;
  }

  return sessions.get(sessionId) || null;
}

function safeUser(user) {
  return {
    name: user.name,
    username: user.username,
    createdAt: user.createdAt
  };
}

async function requireAuth(req, res, next) {
  const username = getSessionUsername(req);

  if (!username) {
    res.status(401).json({ error: '로그인이 필요합니다.' });
    return;
  }

  const users = await readUsers();
  const user = users.find((item) => item.username === username);

  if (!user) {
    res.status(401).json({ error: '로그인이 필요합니다.' });
    return;
  }

  req.currentUser = user;
  next();
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.post('/api/signup', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const privatePassword = String(req.body.privatePassword || '');

  if (!name) {
    res.status(400).json({ error: '이름을 입력하세요.' });
    return;
  }

  if (username.length < 3) {
    res.status(400).json({ error: '아이디는 3자 이상이어야 합니다.' });
    return;
  }

  if (password.length < 6) {
    res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });
    return;
  }

  if (privatePassword !== privateAccessPassword) {
    res.status(400).json({ error: '비공개 전용 비밀번호가 올바르지 않습니다.' });
    return;
  }

  const users = await readUsers();
  const duplicateUser = users.some((user) => user.username.toLowerCase() === username.toLowerCase());

  if (duplicateUser) {
    res.status(409).json({ error: '이미 사용 중인 아이디입니다.' });
    return;
  }

  const passwordRecord = createPasswordRecord(password);
  const newUser = {
    id: crypto.randomUUID(),
    name,
    username,
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await saveUsers(users);

  const sessionId = createSession(newUser.username);
  setSessionCookie(res, sessionId);

  res.status(201).json({ user: safeUser(newUser) });
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const privatePassword = String(req.body.privatePassword || '');

  if (privatePassword !== privateAccessPassword) {
    res.status(400).json({ error: '비공개 전용 비밀번호가 올바르지 않습니다.' });
    return;
  }

  const users = await readUsers();
  const user = users.find((item) => item.username.toLowerCase() === username.toLowerCase());

  if (!user) {
    res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    return;
  }

  const passwordValid = verifyPassword(password, user.passwordSalt, user.passwordHash);

  if (!passwordValid) {
    res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    return;
  }

  const sessionId = createSession(user.username);
  setSessionCookie(res, sessionId);

  res.json({ user: safeUser(user) });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');

  if (newPassword.length < 6) {
    res.status(400).json({ error: '새 비밀번호는 6자 이상이어야 합니다.' });
    return;
  }

  const users = await readUsers();
  const userIndex = users.findIndex((item) => item.username === req.currentUser.username);

  if (userIndex === -1) {
    res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    return;
  }

  const user = users[userIndex];
  const currentPasswordValid = verifyPassword(currentPassword, user.passwordSalt, user.passwordHash);

  if (!currentPasswordValid) {
    res.status(401).json({ error: '현재 비밀번호가 올바르지 않습니다.' });
    return;
  }

  const passwordRecord = createPasswordRecord(newPassword);
  users[userIndex] = {
    ...user,
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash
  };

  await saveUsers(users);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: safeUser(req.currentUser) });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[sessionCookieName];
  if (sessionId) {
    sessions.delete(sessionId);
  }

  clearSessionCookie(res);
  res.json({ ok: true });
});

function validateCategory(category) {
  return allowedCategories.includes(category) ? category : '일반';
}

function buildImagePayload(file) {
  if (!file) {
    return null;
  }

  if (!String(file.mimetype || '').startsWith('image/')) {
    const error = new Error('이미지 파일만 업로드할 수 있습니다.');
    error.statusCode = 400;
    throw error;
  }

  return {
    name: file.originalname,
    mimeType: file.mimetype,
    dataUrl: `data:${file.mimetype};base64,${file.buffer.toString('base64')}`
  };
}

function findPostIndex(posts, postId) {
  return posts.findIndex((post) => post.id === postId);
}

app.get('/api/posts', requireAuth, async (req, res) => {
  const posts = await readPosts();
  res.json(posts);
});

app.post('/api/posts', requireAuth, upload.single('image'), async (req, res) => {
  const title = String(req.body.title || '').trim();
  const content = String(req.body.content || '').trim();
  const category = validateCategory(String(req.body.category || '').trim());

  if (!title) {
    res.status(400).json({ error: '제목을 입력하세요.' });
    return;
  }

  if (!content) {
    res.status(400).json({ error: '내용을 입력하세요.' });
    return;
  }

  const posts = await readPosts();
  const newPost = {
    id: crypto.randomUUID(),
    title,
    content,
    category,
    authorName: req.currentUser.name,
    authorUsername: req.currentUser.username,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    image: buildImagePayload(req.file),
    hearts: [],
    comments: []
  };

  posts.unshift(newPost);
  await savePosts(posts);
  res.status(201).json(newPost);
});

app.put('/api/posts/:id', requireAuth, upload.single('image'), async (req, res) => {
  const postId = String(req.params.id || '');
  const title = String(req.body.title || '').trim();
  const content = String(req.body.content || '').trim();
  const category = validateCategory(String(req.body.category || '').trim());

  if (!title) {
    res.status(400).json({ error: '제목을 입력하세요.' });
    return;
  }

  if (!content) {
    res.status(400).json({ error: '내용을 입력하세요.' });
    return;
  }

  const posts = await readPosts();
  const index = findPostIndex(posts, postId);

  if (index === -1) {
    res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    return;
  }

  if (posts[index].authorUsername !== req.currentUser.username) {
    res.status(403).json({ error: '자신의 게시물만 수정할 수 있습니다.' });
    return;
  }

  const updatedPost = {
    ...posts[index],
    title,
    content,
    category,
    updatedAt: new Date().toISOString(),
    image: req.file ? buildImagePayload(req.file) : posts[index].image || null
  };

  posts[index] = updatedPost;
  await savePosts(posts);
  res.json(updatedPost);
});

app.post('/api/posts/:id/hearts', requireAuth, async (req, res) => {
  const postId = String(req.params.id || '');
  const posts = await readPosts();
  const index = findPostIndex(posts, postId);

  if (index === -1) {
    res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    return;
  }

  const hearts = new Set(posts[index].hearts || []);
  if (hearts.has(req.currentUser.username)) {
    hearts.delete(req.currentUser.username);
  } else {
    hearts.add(req.currentUser.username);
  }

  posts[index].hearts = Array.from(hearts);
  posts[index].updatedAt = new Date().toISOString();
  await savePosts(posts);
  res.json(posts[index]);
});

app.post('/api/posts/:id/comments', requireAuth, async (req, res) => {
  const postId = String(req.params.id || '');
  const content = String(req.body.content || '').trim();

  if (!content) {
    res.status(400).json({ error: '댓글 내용을 입력하세요.' });
    return;
  }

  const posts = await readPosts();
  const index = findPostIndex(posts, postId);

  if (index === -1) {
    res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    return;
  }

  const newComment = normalizeComment({
    id: crypto.randomUUID(),
    content,
    authorName: req.currentUser.name,
    authorUsername: req.currentUser.username,
    createdAt: new Date().toISOString()
  });

  posts[index].comments = Array.isArray(posts[index].comments) ? posts[index].comments : [];
  posts[index].comments.push(newComment);
  posts[index].updatedAt = new Date().toISOString();
  await savePosts(posts);
  res.status(201).json(newComment);
});

app.delete('/api/posts/:postId/comments/:commentId', requireAuth, async (req, res) => {
  const postId = String(req.params.postId || '');
  const commentId = String(req.params.commentId || '');
  const posts = await readPosts();
  const index = findPostIndex(posts, postId);

  if (index === -1) {
    res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    return;
  }

  const comments = Array.isArray(posts[index].comments) ? posts[index].comments : [];
  const commentIndex = comments.findIndex((comment) => comment.id === commentId);

  if (commentIndex === -1) {
    res.status(404).json({ error: '댓글을 찾을 수 없습니다.' });
    return;
  }

  const comment = comments[commentIndex];
  const canDelete = comment.authorUsername === req.currentUser.username || posts[index].authorUsername === req.currentUser.username;

  if (!canDelete) {
    res.status(403).json({ error: '댓글을 삭제할 권한이 없습니다.' });
    return;
  }

  comments.splice(commentIndex, 1);
  posts[index].comments = comments;
  posts[index].updatedAt = new Date().toISOString();
  await savePosts(posts);
  res.json({ ok: true });
});

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  const postId = String(req.params.id || '');
  const posts = await readPosts();
  const index = posts.findIndex((post) => post.id === postId);

  if (index === -1) {
    res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    return;
  }

  if (posts[index].authorUsername !== req.currentUser.username) {
    res.status(403).json({ error: '자신의 게시물만 삭제할 수 있습니다.' });
    return;
  }

  posts.splice(index, 1);
  await savePosts(posts);
  res.json({ ok: true });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(rootDir, 'index.html'));
});

app.use((error, req, res, next) => {
  if (error && error.code === 'LIMIT_FILE_SIZE') {
    res.status(413).json({ error: '이미지 파일은 최대 8MB까지만 업로드할 수 있습니다.' });
    return;
  }

  if (error && error.statusCode) {
    res.status(error.statusCode).json({ error: error.message || '요청을 처리하지 못했습니다.' });
    return;
  }

  next(error);
});

ensureDataFiles()
  .then(() => {
    app.listen(port, () => {
      console.log(`BloGoneuk server running at http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.error('Failed to initialize server storage:', error);
    process.exit(1);
  });
