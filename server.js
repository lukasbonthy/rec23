'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 2059);
const DATA_DIR = path.join(__dirname, 'Data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'sscs_default_secret_key_must_be_over_32_chars_long';
const GAME_VERSION = 20230406;
const EMPTY = [];

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readJson(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(file, value) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}

function nowIso() {
  return new Date().toISOString();
}

function randomId(min = 1000, max = 999999999) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function uuid() {
  return crypto.randomUUID();
}

function safeFileName(name) {
  return path.basename(String(name || '').replace(/\\/g, '/'));
}

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(input) {
  input = String(input).replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString('utf8');
}

function signJwt(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 60 * 60 * 24 * 30;
  const fullPayload = { iss: 'sscs', iat, exp, role: ['developer'], ...payload };
  const encodedHeader = b64url(JSON.stringify(header));
  const encodedPayload = b64url(JSON.stringify(fullPayload));
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${encodedHeader}.${encodedPayload}`).digest();
  return `${encodedHeader}.${encodedPayload}.${b64url(signature)}`;
}

function verifyJwt(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest());
    const a = Buffer.from(s);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(b64urlDecode(p));
    if (payload.iss !== 'sscs') return null;
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function getAuthId(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  const payload = verifyJwt(auth.slice(7).trim());
  const id = payload && payload.sub ? Number(payload.sub) : null;
  return Number.isFinite(id) ? id : null;
}

function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/$/, '');
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`.replace(/\/$/, '');
}

function contentTypeFor(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  return {
    '.room': 'application/octet-stream',
    '.bin': 'application/octet-stream',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.txt': 'text/plain; charset=utf-8'
  }[ext] || 'application/octet-stream';
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, JSON.stringify(value), {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*'
  });
}

function sendText(res, status, value) {
  send(res, status, String(value ?? ''), {
    'content-type': 'text/plain; charset=utf-8',
    'access-control-allow-origin': '*'
  });
}

function notFound(res) {
  sendJson(res, 404, { error: 'Not found' });
}

function unauthorized(res) {
  sendJson(res, 401, { error: 'Unauthorized' });
}

function forbidden(res) {
  sendJson(res, 403, { error: 'Forbidden' });
}

function serveFile(res, filePath, downloadName = null) {
  if (!filePath || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return notFound(res);
  const headers = {
    'content-type': contentTypeFor(filePath),
    'access-control-allow-origin': '*',
    'cache-control': 'public, max-age=14400'
  };
  if (downloadName) headers['content-disposition'] = `inline; filename="${safeFileName(downloadName)}"`;
  res.writeHead(200, headers);
  fs.createReadStream(filePath).pipe(res);
}

function bufferSplit(buffer, separator) {
  const out = [];
  let start = 0;
  let index = buffer.indexOf(separator, start);
  while (index !== -1) {
    out.push(buffer.slice(start, index));
    start = index + separator.length;
    index = buffer.indexOf(separator, start);
  }
  out.push(buffer.slice(start));
  return out;
}

function parseUrlEncoded(str) {
  const params = new URLSearchParams(str);
  const obj = {};
  for (const [k, v] of params.entries()) {
    if (obj[k] === undefined) obj[k] = v;
    else if (Array.isArray(obj[k])) obj[k].push(v);
    else obj[k] = [obj[k], v];
  }
  return obj;
}

function parseMultipart(buffer, contentType) {
  const match = /boundary=(?:(?:"([^"]+)")|([^;]+))/i.exec(contentType || '');
  if (!match) return { fields: {}, files: [] };
  const boundary = Buffer.from(`--${match[1] || match[2]}`);
  const parts = bufferSplit(buffer, boundary).slice(1, -1);
  const fields = {};
  const files = [];

  for (let part of parts) {
    if (part.slice(0, 2).toString() === '\r\n') part = part.slice(2);
    if (part.slice(-2).toString() === '\r\n') part = part.slice(0, -2);
    const headerEnd = part.indexOf(Buffer.from('\r\n\r\n'));
    if (headerEnd < 0) continue;
    const rawHeaders = part.slice(0, headerEnd).toString('utf8');
    const body = part.slice(headerEnd + 4);
    const disp = /content-disposition:\s*form-data;([^\r\n]+)/i.exec(rawHeaders);
    if (!disp) continue;
    const name = /name="([^"]+)"/i.exec(disp[1])?.[1];
    const filename = /filename="([^"]*)"/i.exec(disp[1])?.[1];
    const ctype = /content-type:\s*([^\r\n]+)/i.exec(rawHeaders)?.[1]?.trim();
    if (!name) continue;
    if (filename !== undefined && filename !== '') {
      files.push({ fieldName: name, filename: safeFileName(filename), contentType: ctype || 'application/octet-stream', buffer: body });
    } else {
      fields[name] = body.toString('utf8');
    }
  }
  return { fields, files };
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 100 * 1024 * 1024) throw new Error('Body too large');
    chunks.push(chunk);
  }
  const buffer = Buffer.concat(chunks);
  const type = req.headers['content-type'] || '';
  const raw = buffer.toString('utf8');

  if (type.includes('application/json')) {
    try { return { raw, fields: JSON.parse(raw || '{}'), files: [] }; } catch { return { raw, fields: {}, files: [] }; }
  }
  if (type.includes('application/x-www-form-urlencoded')) {
    return { raw, fields: parseUrlEncoded(raw), files: [] };
  }
  if (type.includes('multipart/form-data')) {
    const parsed = parseMultipart(buffer, type);
    return { raw, fields: parsed.fields, files: parsed.files };
  }
  return { raw, fields: raw ? parseUrlEncoded(raw) : {}, files: [] };
}

function getQueryArray(url, key) {
  const values = url.searchParams.getAll(key);
  const result = [];
  for (const v of values) {
    String(v).split(',').forEach(x => {
      const n = Number(x);
      if (Number.isFinite(n)) result.push(n);
    });
  }
  return result;
}

function findFileRecursive(root, name) {
  if (!fs.existsSync(root)) return null;
  const direct = path.join(root, name);
  if (fs.existsSync(direct) && fs.statSync(direct).isFile()) return direct;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, item.name);
      if (item.isDirectory()) stack.push(p);
      else if (item.isFile() && item.name === name) return p;
    }
  }
  return null;
}

function defaultAvatar() {
  return { OutfitSelections: '', FaceFeatures: '', SkinColor: '', HairColor: '' };
}

function defaultHeartbeat(playerId = 0) {
  return {
    appVersion: String(GAME_VERSION),
    deviceClass: 0,
    errorCode: null,
    isOnline: false,
    playerId,
    roomInstance: null,
    statusVisibility: 0,
    vrMovementMode: 0
  };
}

function defaultReputation(accountId = 0) {
  return {
    AccountId: accountId,
    IsCheerful: false,
    Noteriety: 0,
    SelectedCheer: 0,
    CheerCredit: 0,
    CheerGeneral: 0,
    CheerHelpful: 0,
    CheerCreative: 0,
    CheerGreatHost: 0,
    CheerSportsman: 0,
    SubscriberCount: 0,
    SubscribedCount: 0
  };
}

function defaultSettings() {
  return [
    { Key: 'Recroom.AccountCreation.HasStarted', Value: 'True' },
    { Key: 'Recroom.AccountCreation.HasChosenUsername', Value: 'True' },
    { Key: 'Recroom.AccountCreation.HasCreatedPassword', Value: 'True' },
    { Key: 'Recroom.AccountCreation.HasFinished', Value: 'True' },
    { Key: 'TUTORIAL_COMPLETE_MASK', Value: '57' }
  ];
}

const nameWords = ['Coach', 'Pixel', 'Sky', 'Lunar', 'Echo', 'Neon', 'Quest', 'Orbit', 'Nova', 'Rec'];
function randomUsername() {
  return `${nameWords[Math.floor(Math.random() * nameWords.length)]}${Math.floor(Math.random() * 90000) + 10000}`;
}

function normalizeRoom(room) {
  room.RoomId = Number(room.RoomId);
  room.Name = room.Name || `Room${room.RoomId}`;
  room.Description = room.Description || '';
  room.ImageName = room.ImageName || 'DefaultRoomImage.png';
  room.CreatedAt = room.CreatedAt || nowIso();
  room.Stats = room.Stats || { CheerCount: 0, FavoriteCount: 0, VisitorCount: 0, VisitCount: 0 };
  room.SubRooms = room.SubRooms || [];
  room.Roles = room.Roles || [];
  room.Tags = room.Tags || [];
  room.PromoImages = room.PromoImages || [];
  room.PromoExternalContent = room.PromoExternalContent || [];
  room.LoadScreens = room.LoadScreens || [];
  room.SupportsScreens = room.SupportsScreens !== false;
  room.Accessibility = room.Accessibility ?? 1;
  room.CreatorAccountId = Number(room.CreatorAccountId || 2);
  room.MaxPlayers = Number(room.MaxPlayers || 4);
  room.UgcVersion = Number(room.UgcVersion || 1);
  room.PersistenceVersion = Number(room.PersistenceVersion || 0);
  room.RankedEntityId = room.RankedEntityId || String(room.RoomId);
  for (const sub of room.SubRooms) {
    sub.SubRoomId = Number(sub.SubRoomId);
    sub.RoomId = Number(sub.RoomId || room.RoomId);
    sub.Name = sub.Name || 'Home';
    sub.MaxPlayers = Number(sub.MaxPlayers || room.MaxPlayers || 4);
    sub.Accessibility = sub.Accessibility ?? room.Accessibility;
    sub.UnitySceneId = sub.UnitySceneId || '';
    sub.SavedByAccountId = Number(sub.SavedByAccountId || room.CreatorAccountId || 0);
  }
  return room;
}

function seedDb() {
  ensureDir(DATA_DIR);
  ensureDir(path.join(DATA_DIR, 'Images'));
  ensureDir(path.join(DATA_DIR, 'cdn'));
  ensureDir(path.join(DATA_DIR, 'cdn', 'video'));

  let rooms = readJson(path.join(DATA_DIR, 'Imports', 'ImportRooms.json'), []);
  rooms = Array.isArray(rooms) ? rooms.map(normalizeRoom) : [];
  return {
    players: [],
    rooms,
    inventions: [],
    inventionVersions: [],
    events: [],
    subRoomSaves: [],
    nextPlayerId: 1000,
    nextRoomId: Math.max(1000, ...rooms.map(r => Number(r.RoomId) || 0)) + 1,
    nextInventionId: 1,
    nextEventId: 1,
    nextSubRoomSaveId: 1
  };
}

let db = fs.existsSync(DB_PATH) ? readJson(DB_PATH, null) : null;
if (!db) {
  db = seedDb();
  writeJsonAtomic(DB_PATH, db);
} else {
  db.players ||= [];
  db.rooms = Array.isArray(db.rooms) ? db.rooms.map(normalizeRoom) : seedDb().rooms;
  db.inventions ||= [];
  db.inventionVersions ||= [];
  db.events ||= [];
  db.subRoomSaves ||= [];
  db.nextPlayerId ||= Math.max(1000, ...db.players.map(p => Number(p.PlayerId) || 0)) + 1;
  db.nextRoomId ||= Math.max(1000, ...db.rooms.map(r => Number(r.RoomId) || 0)) + 1;
  db.nextInventionId ||= Math.max(1, ...db.inventions.map(i => Number(i.InventionId) || 0)) + 1;
  db.nextEventId ||= Math.max(1, ...db.events.map(e => Number(e.EventId) || 0)) + 1;
  db.nextSubRoomSaveId ||= Math.max(1, ...db.subRoomSaves.map(s => Number(s.SubRoomDataSaveId) || 0)) + 1;
}

function saveDb() {
  writeJsonAtomic(DB_PATH, db);
}

function createAccount(platform = 0, platformId = Date.now(), isJunior = false) {
  const id = db.nextPlayerId++;
  const username = randomUsername();
  const created = nowIso();
  const player = {
    PlayerId: id,
    PlatformIds: [{ Platform: Number(platform) || 0, PlatformId: String(platformId) }],
    DeviceIds: [],
    AuthToken: uuid(),
    Password: null,
    PlayerRoles: [30, 20, 255],
    Player: {
      Username: username,
      DisplayName: username,
      Bio: '',
      AvailableUsernameChanges: 3,
      IsJunior: Boolean(isJunior),
      Level: 1,
      XP: 0,
      ProfileImage: 'DefaultPFP.png',
      BannerImage: null,
      Email: null,
      CreatedAt: created,
      LastLoginAt: created,
      Birthday: null,
      CurrentAuthSession: { AuthSigningKey: null },
      Reputation: defaultReputation(id),
      VisitedRooms: [],
      RoomVisits: [],
      CheeredRooms: [],
      FavoritedRooms: [],
      Relationships: [],
      PlayerExtra: {
        Avatar: defaultAvatar(),
        AvatarItems: [],
        SavedAvatars: [],
        ModerationBlockDetails: {
          ReportCategory: 0,
          Duration: 0,
          GameSessionId: 0,
          IsBan: false,
          IsHostKick: false,
          Message: '',
          PlayerIdReporter: null
        },
        Settings: defaultSettings(),
        Heartbeat: defaultHeartbeat(id),
        Currencies: []
      }
    }
  };
  db.players.push(player);
  saveDb();
  return player;
}

function findPlayer(id) {
  return db.players.find(p => Number(p.PlayerId) === Number(id));
}

function findPlayerByPlatform(platform, platformId) {
  return db.players.filter(p => (p.PlatformIds || []).some(pid => Number(pid.Platform) === Number(platform) && String(pid.PlatformId) === String(platformId)));
}

function currentPlayer(req) {
  const id = getAuthId(req);
  return id == null ? null : findPlayer(id);
}

function mapAccount(p, me = false) {
  const pl = p?.Player || {};
  const platforms = (p.PlatformIds || []).reduce((acc, pid) => acc | (Number(pid.Platform) || 0), 0);
  const out = {
    accountId: Number(p.PlayerId),
    createdAt: pl.CreatedAt || nowIso(),
    displayName: pl.DisplayName || pl.Username || '',
    isJunior: Boolean(pl.IsJunior),
    platforms,
    profileImage: pl.ProfileImage || 'DefaultPFP.png',
    username: pl.Username || '',
    personalPronouns: 0,
    identityFlags: 0
  };
  if (me) {
    out.availableUsernameChanges = Number(pl.AvailableUsernameChanges || 3);
    out.birthday = pl.Birthday || null;
    out.email = pl.Email || null;
    out.phone = null;
  }
  return out;
}

function relationshipFor(player, targetId) {
  const pl = player.Player;
  pl.Relationships ||= [];
  let rel = pl.Relationships.find(r => Number(r.PlayerId) === Number(targetId));
  if (!rel) {
    rel = { PlayerId: Number(targetId), Favorited: 0, Ignored: 0, Muted: 0, RelationshipType: 0 };
    pl.Relationships.push(rel);
  }
  return rel;
}

function publicRelationship(rel) {
  return {
    Favorited: rel.Favorited || 0,
    Ignored: rel.Ignored || 0,
    Muted: rel.Muted || 0,
    PlayerID: rel.PlayerId,
    RelationshipType: rel.RelationshipType || 0
  };
}

function findRoom(id) {
  return db.rooms.find(r => Number(r.RoomId) === Number(id));
}

function findRoomByName(name) {
  return db.rooms.find(r => String(r.Name || '').toLowerCase() === String(name || '').toLowerCase());
}

function roomHasTag(room, tag) {
  return (room.Tags || []).some(t => String(t.Tag || t).toLowerCase() === String(tag).toLowerCase());
}

function playerHasFavorite(playerId, roomId) {
  const p = findPlayer(playerId);
  return Boolean(p?.Player?.FavoritedRooms?.map(Number).includes(Number(roomId)));
}

function playerHasCheer(playerId, roomId) {
  const p = findPlayer(playerId);
  return Boolean(p?.Player?.CheeredRooms?.map(Number).includes(Number(roomId)));
}

function roomLastVisited(playerId, roomId) {
  const p = findPlayer(playerId);
  const visit = p?.Player?.RoomVisits?.find(v => Number(v.RoomId) === Number(roomId));
  return visit?.LastVisitedAt || null;
}

function setPlayerSetting(player, key, value) {
  const settings = player.Player.PlayerExtra.Settings ||= [];
  const found = settings.find(s => s.Key === key);
  if (found) found.Value = String(value ?? '');
  else settings.push({ Key: key, Value: String(value ?? '') });
  saveDb();
}

function createRoomInstance(playerId, roomId, subRoomId = null) {
  const room = findRoom(roomId);
  if (!room) return null;
  const sub = subRoomId != null
    ? (room.SubRooms || []).find(s => Number(s.SubRoomId) === Number(subRoomId))
    : (room.SubRooms || [])[0];
  if (!sub) return null;

  const instanceNumber = randomId();
  const roomName = room.Name || 'UnknownRoom';
  const session = {
    encryptVoiceChat: false,
    clubId: 0,
    dataBlob: sub.DataBlob || '',
    eventId: 0,
    isFull: false,
    isInProgress: false,
    isPrivate: false,
    location: sub.UnitySceneId || '',
    maxCapacity: Number(sub.MaxPlayers || room.MaxPlayers || 4),
    Name: `^${roomName}`,
    photonRegion: 'us',
    photonRegionId: 'us',
    photonRoomId: `sscsRoom-${roomName}-room`,
    roomCode: '',
    roomId: Number(room.RoomId),
    roomInstanceId: instanceNumber,
    roomInstanceType: 0,
    subRoomId: Number(sub.SubRoomId)
  };
  return updateHeartbeat(playerId, session);
}

function createDormInstance(playerId) {
  const p = findPlayer(playerId);
  const name = p?.Player?.Username || 'Player';
  const dorm = findRoom(1);
  const sub = dorm?.SubRooms?.[0];
  const instanceId = randomId();
  const session = {
    encryptVoiceChat: false,
    clubId: 0,
    dataBlob: sub?.DataBlob || '',
    eventId: 0,
    isFull: false,
    isInProgress: false,
    isPrivate: true,
    location: sub?.UnitySceneId || '76d98498-60a1-430c-ab76-b54a29b7a163',
    maxCapacity: 4,
    Name: `@${name}'s Dorm`,
    photonRegion: 'us',
    photonRegionId: 'us',
    photonRoomId: `sscsDorm-${instanceId}-room`,
    roomCode: '',
    roomId: 1,
    roomInstanceId: instanceId,
    roomInstanceType: 0,
    subRoomId: Number(sub?.SubRoomId || 0)
  };
  return updateHeartbeat(playerId, session);
}

function updateHeartbeat(playerId, roomInstance = undefined) {
  const p = findPlayer(playerId);
  if (!p) return null;
  p.Player.PlayerExtra.Heartbeat ||= defaultHeartbeat(playerId);
  const hb = p.Player.PlayerExtra.Heartbeat;
  hb.playerId = Number(playerId);
  hb.isOnline = true;
  hb.appVersion = String(GAME_VERSION);
  if (roomInstance !== undefined) hb.roomInstance = roomInstance;
  saveDb();
  return hb;
}

function cloneRoom(original, name, creatorId) {
  const clone = JSON.parse(JSON.stringify(original));
  clone.RoomId = db.nextRoomId++;
  clone.Name = name;
  clone.CreatedAt = nowIso();
  clone.RankedEntityId = String(clone.RoomId);
  clone.ImageName = 'DefaultRoomImage.png';
  clone.Accessibility = 0;
  clone.CloningAllowed = false;
  clone.IsRRO = false;
  clone.IsDeveloperOwned = false;
  clone.PromoImages = [];
  clone.CreatorAccountId = Number(creatorId);
  clone.Stats = { CheerCount: 0, FavoriteCount: 0, VisitorCount: 0, VisitCount: 0 };
  clone.Tags = (clone.Tags || []).filter(t => !['base', 'rro'].includes(String(t.Tag || t).toLowerCase()));
  let subId = Math.max(1, ...db.rooms.flatMap(r => (r.SubRooms || []).map(s => Number(s.SubRoomId) || 0))) + 1;
  for (const sub of clone.SubRooms || []) {
    sub.SubRoomId = subId++;
    sub.RoomId = clone.RoomId;
    sub.SavedByAccountId = Number(creatorId);
  }
  clone.Roles = [{ AccountId: Number(creatorId), Role: 255, InvitedRole: 255 }];
  db.rooms.push(normalizeRoom(clone));
  saveDb();
  return clone;
}

function inventionData(inv) {
  return {
    AllowTrial: Boolean(inv.AllowTrial),
    CheerCount: Number(inv.CheerCount || 0),
    CreatedAt: inv.CreatedAt || nowIso(),
    CreatorPermission: Number(inv.CreatorPermission || 0),
    CreatorPlayerId: Number(inv.CreatorPlayerId || 0),
    CurrentVersionNumber: Number(inv.CurrentVersionNumber || 1),
    Description: inv.Description || '',
    GeneralPermission: Number(inv.GeneralPermission || 0),
    HideFromPlayer: Boolean(inv.HideFromPlayer),
    ImageName: inv.ImageName || '',
    InventionId: Number(inv.InventionId),
    IsAGInvention: Boolean(inv.IsAGInvention),
    IsCertifiedInvention: Boolean(inv.IsCertifiedInvention),
    IsPublished: Boolean(inv.IsPublished),
    ModifiedAt: inv.ModifiedAt || inv.CreatedAt || nowIso(),
    Name: inv.Name || '',
    NumDownloads: Number(inv.NumDownloads || 0),
    NumPlayersHaveUsedInRoom: Number(inv.NumPlayersHaveUsedInRoom || 0),
    Price: Number(inv.Price || 0),
    ReplicationId: inv.ReplicationId || ''
  };
}

const routes = [];
function compileRoute(pattern) {
  const keys = [];
  let regex = '^' + pattern.replace(/\/$/, '').replace(/\/:(\w+)/g, (_, key) => {
    keys.push(key);
    return '/([^/]+)';
  }).replace(/\/\*(\w+)/g, (_, key) => {
    keys.push(key);
    return '/(.*)';
  }) + '/?$';
  return { regex: new RegExp(regex), keys };
}

function route(method, pattern, handler) {
  const compiled = compileRoute(pattern);
  routes.push({ method: method.toUpperCase(), pattern, ...compiled, handler });
}

function get(pattern, handler) { route('GET', pattern, handler); }
function post(pattern, handler) { route('POST', pattern, handler); }
function put(pattern, handler) { route('PUT', pattern, handler); }
function del(pattern, handler) { route('DELETE', pattern, handler); }

function authRequired(req, res) {
  const id = getAuthId(req);
  if (id == null) {
    unauthorized(res);
    return null;
  }
  return id;
}

get('/', (req, res) => {
  const url = getBaseUrl(req);
  sendJson(res, 200, {
    Accounts: `${url}/acc`, API: url, Auth: `${url}/auth`, BugReporting: url, Cards: url, CDN: `${url}/cdn`,
    Chat: url, Clubs: url, CMS: url, Commerce: url, Data: url, DataCollection: url, Discovery: url,
    Econ: url, GameLogs: url, Geo: url, Images: `${url}/imageserver`, Leaderboard: url, Link: url,
    Lists: url, Matchmaking: `${url}/match`, Moderation: url, Notifications: `${url}/noti`,
    PlatformNotifications: url, PlayerSettings: url, RoomComments: url, Rooms: `${url}/roomserver`,
    Storage: url, Strings: url, StringsCDN: url, Studio: url, Thorn: url, Videos: url, WWW: url
  });
});

get('/api/versioncheck/v4', (req, res) => sendJson(res, 200, {
  ValidVersion: 0, VersionStatus: 0, UpdateNotificationStage: 0, IsVersionIslanded: false, IsCrossPlayDisabled: false
}));

get('/api/gameconfigs/v1/all', (req, res) => serveFile(res, path.join(DATA_DIR, 'APIS', 'GameConfigs.json')));
get('/api/config/v1/amplitude', (req, res) => sendJson(res, 200, {
  AmplitudeKey: 'cb2fb2ecb9953512c29af5bca58f2b4a', UseRudderStack: true,
  RudderStackKey: '23NiJHIgu3koaGNCZIiuYvIQNCu', UseStatSig: true,
  StatSigKey: 'client-SBZkOrjD3r1Cat3f3W8K6sBd11WKlXZXIlCWj6l4Aje', StatSigEnvironment: 0
}));
get('/api/avatar/v1/defaultunlocked', (req, res) => sendJson(res, 200, EMPTY));
get('/api/avatar/v1/defaultbaseavataritems', (req, res) => sendJson(res, 200, EMPTY));

get('/api/config/v2', (req, res) => {
  const cfg = readJson(path.join(DATA_DIR, 'APIS', 'ConfigV2.json'), {});
  const base = getBaseUrl(req);
  if (cfg && typeof cfg === 'object') {
    cfg.CdnBaseUri = `${base}/`;
    cfg.ShareBaseUrl = `${base}/share/0`;
  }
  sendJson(res, 200, cfg);
});

get('/cdn/config/LoadingScreenTipData', (req, res) => serveFile(res, path.join(DATA_DIR, 'APIS', 'LoadingScreenTips.json')));

get('/auth/eac/challenge', (req, res) => sendJson(res, 200, 'skyfiregamezrevival'));
get('/auth/cachedlogin/forplatformid/:platform/:platformId', (req, res) => {
  const platform = Number(req.params.platform);
  const platformId = req.params.platformId;
  let accounts = findPlayerByPlatform(platform, platformId);
  if (!accounts.length) accounts = [createAccount(platform, platformId, false)];
  sendJson(res, 200, accounts.map(p => ({
    platform, platformId: String(platformId), accountId: p.PlayerId,
    lastLoginTime: p.Player?.LastLoginAt || nowIso(), requirePassword: false
  })));
});

post('/auth/auth/cachedlogin/forplatformids', (req, res) => {
  const ids = Array.isArray(req.body.id) ? req.body.id : [req.body.id].filter(Boolean);
  const accounts = [];
  for (const id of ids) {
    for (const p of findPlayerByPlatform(0, id)) {
      accounts.push({ platform: 0, platformId: String(id), accountId: p.PlayerId, lastLoginTime: p.Player?.LastLoginAt || nowIso(), requirePassword: false });
    }
  }
  sendJson(res, 200, accounts.sort((a, b) => String(b.lastLoginTime).localeCompare(String(a.lastLoginTime))));
});

post('/auth/connect/token', (req, res) => {
  const body = req.body || {};
  const grant = body.grant_type;
  if (grant === 'cached_login') {
    const accountId = Number(body.account_id);
    if (!findPlayer(accountId)) createAccount(Number(body.platform || 0), body.platform_id || Date.now(), false).PlayerId = accountId;
    return sendJson(res, 200, { access_token: signJwt({ sub: String(accountId) }), error: '', error_description: '', refresh_token: 'skyfire', key: '' });
  }
  if (grant === 'create_account') {
    const p = createAccount(Number(body.platform || 0), body.platform_id || Date.now(), false);
    return sendJson(res, 200, { access_token: signJwt({ sub: String(p.PlayerId) }), error: '', error_description: '', refresh_token: 'skyfire', key: '' });
  }
  sendJson(res, 400, { error: 'unsupported_grant_type' });
});

get('/acc/account/bulk', (req, res) => {
  const ids = getQueryArray(req.urlObj, 'id');
  sendJson(res, 200, db.players.filter(p => ids.includes(Number(p.PlayerId))).map(p => mapAccount(p)));
});

get('/acc/account/me', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const p = findPlayer(id); if (!p) return notFound(res);
  sendJson(res, 200, mapAccount(p, true));
});

post('/acc/account/me/email', (req, res) => sendJson(res, 200, { success: true }));
put('/acc/account/me/profileimage', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const p = findPlayer(id); if (!p) return notFound(res);
  const imageName = req.body.imageName;
  if (!imageName) return sendText(res, 400, 'Missing imageName');
  p.Player.ProfileImage = imageName;
  saveDb();
  sendJson(res, 200, {});
});

get('/role/moderator/:playerId', (req, res) => {
  const p = findPlayer(req.params.playerId); if (!p) return notFound(res);
  sendJson(res, 200, (p.PlayerRoles || []).map(Number).includes(20));
});
get('/role/developer/:playerId', (req, res) => {
  const p = findPlayer(req.params.playerId); if (!p) return notFound(res);
  sendJson(res, 200, (p.PlayerRoles || []).map(Number).includes(30));
});

get('/acc/account/search', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const name = String(req.urlObj.searchParams.get('name') || '').trim();
  if (!name) return sendJson(res, 200, []);
  const q = name.startsWith('@') ? name.slice(1).toLowerCase() : name.toLowerCase();
  let results = db.players.filter(p => {
    const u = String(p.Player?.Username || '').toLowerCase();
    const d = String(p.Player?.DisplayName || '').toLowerCase();
    return name.startsWith('@') ? u === q : (u.includes(q) || d.includes(q));
  });
  results = results.slice(0, 50).map(p => mapAccount(p));
  sendJson(res, 200, results);
});

get('/api/objectives/v1/myprogress', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  sendJson(res, 200, { Objectives: [], ObjectiveGroups: [] });
});
get('/api/avatar/v2', (req, res) => {
  const p = currentPlayer(req); if (!p) return unauthorized(res);
  sendJson(res, 200, p.Player.PlayerExtra.Avatar || defaultAvatar());
});
get('/api/avatar/v2/:playerId', (req, res) => {
  const p = findPlayer(req.params.playerId); if (!p) return notFound(res);
  sendJson(res, 200, p.Player.PlayerExtra.Avatar || defaultAvatar());
});
post('/api/avatar/v2/set', (req, res) => {
  const p = currentPlayer(req); if (!p) return unauthorized(res);
  p.Player.PlayerExtra.Avatar = { ...defaultAvatar(), ...(req.body || {}) };
  saveDb();
  sendJson(res, 200, p.Player.PlayerExtra.Avatar);
});
get('/api/avatar/v4/items', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  serveFile(res, path.join(DATA_DIR, 'APIS', 'Items', 'AvatarItems.json'));
});
get('/api/PlayerReporting/v1/moderationBlockDetails', (req, res) => {
  const p = currentPlayer(req); if (!p) return unauthorized(res);
  sendJson(res, 200, p.Player.PlayerExtra.ModerationBlockDetails || {});
});
get('/api/relationships/v2/get', (req, res) => {
  const p = currentPlayer(req); if (!p) return unauthorized(res);
  sendJson(res, 200, p.Player.Relationships || []);
});
for (const [action, field, value] of [
  ['mute', 'Muted', 1], ['unmute', 'Muted', 0], ['ignore', 'Ignored', 1], ['unignore', 'Ignored', 0]
]) {
  post(`/api/relationships/v1/${action}`, (req, res) => {
    const p = currentPlayer(req); if (!p) return unauthorized(res);
    const target = Number(req.body.playerId || req.urlObj.searchParams.get('playerId'));
    const rel = relationshipFor(p, target);
    rel[field] = value;
    saveDb();
    sendJson(res, 200, publicRelationship(rel));
  });
}

get('/playersettings', (req, res) => {
  const p = currentPlayer(req); if (!p) return unauthorized(res);
  sendJson(res, 200, p.Player.PlayerExtra.Settings || []);
});
put('/playersettings', (req, res) => {
  const p = currentPlayer(req); if (!p) return unauthorized(res);
  setPlayerSetting(p, req.body.key, req.body.value || '');
  send(res, 204, '');
});

get('/api/players/v2/progression/bulk', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const ids = getQueryArray(req.urlObj, 'id');
  sendJson(res, 200, db.players.filter(p => ids.includes(Number(p.PlayerId))).map(p => ({ PlayerId: p.PlayerId, Level: p.Player?.Level || 1, XP: p.Player?.XP || 0 })));
});
get('/api/playerReputation/v2/bulk', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const ids = getQueryArray(req.urlObj, 'id');
  sendJson(res, 200, db.players.filter(p => ids.includes(Number(p.PlayerId))).map(p => p.Player?.Reputation || defaultReputation(p.PlayerId)));
});

get('/api/messages/v2/get', (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, []); });
get('/econ/customAvatarItems/v1/owned', (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, { Results: [], TotalResults: 0 }); });
get('/api/checklist/v1/current', (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, []); });
post('/api/PlayerReporting/v1/hile', (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, false); });

for (const p of ['/api/announcement/v1/get', '/api/PlayerReporting/v1/voteToKickReasons', '/api/avatar/v3/saved', '/api/images/v2/named', '/api/avatar/v2/gifts', '/api/gamerewards/v1/pending', '/api/roomkeys/v1/mine', '/api/roomcurrencies/v1/currencies']) {
  get(p, (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, []); });
}
get('/api/equipment/v2/getUnlocked', (req, res) => { const id = authRequired(req, res); if (id != null) serveFile(res, path.join(DATA_DIR, 'APIS', 'Items', 'Equipment.json')); });
get('/api/consumables/v2/getUnlocked', (req, res) => { const id = authRequired(req, res); if (id != null) serveFile(res, path.join(DATA_DIR, 'APIS', 'Items', 'Consumables.json')); });
get('/api/playerevents/v1/all', (req, res) => sendJson(res, 200, { Created: [], Responses: [] }));
get('/api/customAvatarItems/v1/isCreationAllowedForAccount', (req, res) => sendJson(res, 200, { success: true, value: null }));
get('/api/customAvatarItems/v1/isCreationEnabled', (req, res) => sendJson(res, 200, true));
get('/api/customAvatarItems/v1/isRenderingEnabled', (req, res) => sendJson(res, 200, true));
get('/api/images/v6', (req, res) => {
  const name = req.urlObj.searchParams.get('name');
  if (!name) return sendJson(res, 400, { error: 'name required' });
  sendJson(res, 200, { fileName: name });
});
get('/api/images/v4/room/:roomId', (req, res) => sendJson(res, 200, {}));
get('/api/roomconsumables/v1/roomConsumable/room/:roomId', (req, res) => sendJson(res, 200, []));
post('/api/sanitize/v1', (req, res) => sendJson(res, 200, JSON.stringify(req.body.Value || req.body.value || '')));
post('/api/sanitize/v1/isPure', (req, res) => sendJson(res, 200, { IsPure: true }));
get('/api/influencerpartnerprogram/influencers', (req, res) => {
  const take = Number(req.urlObj.searchParams.get('take') || 0);
  let ids = [2, 12];
  if (take > 0) ids = ids.slice(0, take);
  sendJson(res, 200, { ContinuationToken: null, InfluencerIds: ids });
});

post('/data/heartbeat', (req, res) => sendJson(res, 200, {}));
post('/v1/batch/rudderstack', (req, res) => sendJson(res, 200, {}));

post('/upload', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const file = req.files?.[0]; if (!file) return sendJson(res, 400, { error: 'No file' });
  ensureDir(path.join(DATA_DIR, 'cdn'));
  const extension = String(req.body.fileType || '2') === '1' ? '.room' : '.bin';
  const name = `${uuid()}${extension}`;
  fs.writeFileSync(path.join(DATA_DIR, 'cdn', name), file.buffer);
  sendJson(res, 200, { filename: name });
});
post('/api/images/v4/uploadsaved', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const file = req.files?.[0]; if (!file) return sendJson(res, 400, { error: 'No file' });
  const ext = path.extname(file.filename) || (file.contentType.includes('jpeg') ? '.jpg' : '.png');
  const name = `ImageData${uuid()}${ext}`;
  ensureDir(path.join(DATA_DIR, 'Images'));
  fs.writeFileSync(path.join(DATA_DIR, 'Images', name), file.buffer);
  sendJson(res, 200, { ImageName: name });
});

get('/roomserver/rooms', (req, res) => {
  const name = req.urlObj.searchParams.get('name');
  if (!name) return notFound(res);
  const room = findRoomByName(name);
  room ? sendJson(res, 200, room) : notFound(res);
});
get('/roomserver/rooms/ownedby/:accountId', (req, res) => {
  if (String(req.params.accountId).toLowerCase() === 'me') {
    const id = authRequired(req, res); if (id == null) return;
    const skip = Number(req.urlObj.searchParams.get('skip') || 0);
    const take = Number(req.urlObj.searchParams.get('take') || 9999);
    return sendJson(res, 200, db.rooms.filter(r => Number(r.CreatorAccountId) === id).sort((a, b) => String(b.CreatedAt).localeCompare(String(a.CreatedAt))).slice(skip, skip + take));
  }
  sendJson(res, 200, db.rooms.filter(r => Number(r.CreatorAccountId) === Number(req.params.accountId)));
});
get('/roomserver/rooms/ownedby/me', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const skip = Number(req.urlObj.searchParams.get('skip') || 0);
  const take = Number(req.urlObj.searchParams.get('take') || 9999);
  sendJson(res, 200, db.rooms.filter(r => Number(r.CreatorAccountId) === id).sort((a, b) => String(b.CreatedAt).localeCompare(String(a.CreatedAt))).slice(skip, skip + take));
});
get('/roomserver/rooms/base', (req, res) => sendJson(res, 200, db.rooms.filter(r => roomHasTag(r, 'base'))));
get('/roomserver/rooms/visitedby/me', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const skip = Number(req.urlObj.searchParams.get('skip') || 0);
  const take = Number(req.urlObj.searchParams.get('take') || 9);
  const p = findPlayer(id);
  const visits = p?.Player?.RoomVisits || [];
  const rooms = visits.sort((a, b) => String(b.LastVisitedAt).localeCompare(String(a.LastVisitedAt))).map(v => findRoom(v.RoomId)).filter(Boolean).slice(skip, skip + take);
  sendJson(res, 200, rooms);
});
get('/roomserver/rooms/favoritedby/me', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const p = findPlayer(id);
  const ids = (p?.Player?.FavoritedRooms || []).map(Number);
  sendJson(res, 200, db.rooms.filter(r => ids.includes(Number(r.RoomId))));
});
get('/roomserver/rooms/search', (req, res) => {
  const query = String(req.urlObj.searchParams.get('query') || '').trim();
  if (!query) return sendText(res, 400, 'Query required.');
  const skip = Number(req.urlObj.searchParams.get('skip') || 0);
  const take = Number(req.urlObj.searchParams.get('take') || 100);
  const terms = query.split('|').map(x => x.trim()).filter(Boolean);
  let results = db.rooms.filter(r => Number(r.Accessibility) === 1 || Number(r.Accessibility) === 2);
  for (const term of terms) {
    if (term.startsWith('^')) {
      const exact = term.slice(1).toLowerCase();
      results = results.filter(r => String(r.Name || '').toLowerCase() === exact);
    } else if (term.startsWith('#')) {
      const tag = term.slice(1).split(/\s+/)[0].toLowerCase();
      results = results.filter(r => (r.Tags || []).some(t => String(t.Tag || t).toLowerCase().includes(tag)));
    }
  }
  const scored = results.map(room => {
    const hay = `${room.Name || ''} ${room.Description || ''} ${(room.Tags || []).map(t => t.Tag || t).join(' ')}`.toLowerCase();
    let score = 0;
    for (const term of terms) {
      const q = term.replace(/^[#^]/, '').toLowerCase().split(/\s+/).join(' ');
      if (String(room.Name || '').toLowerCase() === q) score += 1000;
      if (String(room.Name || '').toLowerCase().startsWith(q)) score += 500;
      if (hay.includes(q)) score += 100;
    }
    return { room, score };
  }).filter(x => x.score > 0).sort((a, b) => b.score - a.score).map(x => x.room);
  sendJson(res, 200, { TotalResults: scored.length, Results: scored.slice(skip, skip + take) });
});
get('/roomserver/rooms/hot', (req, res) => {
  const tag = req.urlObj.searchParams.get('tag');
  const skip = Number(req.urlObj.searchParams.get('skip') || 0);
  const take = Number(req.urlObj.searchParams.get('take') || 30);
  let rooms = db.rooms.filter(r => Number(r.Accessibility) === 1 || Number(r.Accessibility) === 2);
  if (tag) rooms = rooms.filter(r => roomHasTag(r, tag));
  rooms = rooms.sort((a, b) => (b.Stats?.VisitCount || 0) - (a.Stats?.VisitCount || 0));
  sendJson(res, 200, { Results: rooms.slice(skip, skip + take), TotalResults: rooms.length });
});
get('/roomserver/rooms/bulk', (req, res) => {
  const names = req.urlObj.searchParams.getAll('name');
  sendJson(res, 200, db.rooms.filter(r => names.some(n => String(r.Name).toLowerCase() === String(n).toLowerCase())));
});
get('/roomserver/rooms/:roomId', (req, res) => {
  const room = findRoom(req.params.roomId);
  room ? sendJson(res, 200, room) : notFound(res);
});
post('/roomserver/rooms/:roomId/clone', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const room = findRoom(req.params.roomId); if (!room) return notFound(res);
  const name = req.body.Name || req.body.name;
  if (!name) return sendText(res, 400, 'Missing name');
  const clone = cloneRoom(room, name, id);
  sendJson(res, 200, { ...clone, success: true, value: clone, error_id: null, error: null });
});
post('/api/rooms/v1/verifyRole', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const room = findRoom(req.urlObj.searchParams.get('roomId') || req.body.roomId);
  const ok = Boolean(room?.Roles?.some(r => Number(r.AccountId) === id && Number(r.Role) === 255));
  sendJson(res, 200, ok);
});
post('/roomserver/rooms/:roomId/accessibility', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const room = findRoom(req.params.roomId); if (!room) return notFound(res);
  const can = room.Roles?.some(r => Number(r.AccountId) === id && Number(r.Role) === 255);
  if (!can) return forbidden(res);
  room.Accessibility = Number(req.body.accessibility ?? req.body.Accessibility ?? 0);
  saveDb();
  sendJson(res, 200, { Success: true });
});
del('/roomserver/rooms/:roomId', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const idx = db.rooms.findIndex(r => Number(r.RoomId) === Number(req.params.roomId));
  if (idx < 0) return notFound(res);
  const room = db.rooms[idx];
  const can = room.Roles?.some(r => Number(r.AccountId) === id && Number(r.Role) === 255);
  if (!can) return forbidden(res);
  db.rooms.splice(idx, 1);
  saveDb();
  sendJson(res, 200, { Success: true });
});
get('/roomserver/photon_access_token', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const hb = findPlayer(id)?.Player?.PlayerExtra?.Heartbeat || defaultHeartbeat(id);
  sendJson(res, 200, { Permissions: [], PhotonAccessToken: '', RoomInstanceId: hb.roomInstance?.roomInstanceId || null });
});
get('/roomserver/rooms/:roomId/interactionby/me', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  sendJson(res, 200, { Cheered: playerHasCheer(id, req.params.roomId), Favorited: playerHasFavorite(id, req.params.roomId), LastVisitedAt: roomLastVisited(id, req.params.roomId) || nowIso() });
});
put('/roomserver/rooms/:roomId/interactionby/me/favorite', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const p = findPlayer(id); p.Player.FavoritedRooms ||= [];
  const room = findRoom(req.params.roomId);
  if (!p.Player.FavoritedRooms.map(Number).includes(Number(req.params.roomId))) {
    p.Player.FavoritedRooms.push(Number(req.params.roomId));
    if (room) room.Stats.FavoriteCount = (room.Stats.FavoriteCount || 0) + 1;
  }
  saveDb(); sendJson(res, 200, { Favorited: true });
});
del('/roomserver/rooms/:roomId/interactionby/me/favorite', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const p = findPlayer(id); p.Player.FavoritedRooms = (p.Player.FavoritedRooms || []).filter(x => Number(x) !== Number(req.params.roomId));
  saveDb(); sendJson(res, 200, { Favorited: false });
});
put('/roomserver/rooms/:roomId/interactionby/me/cheer', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const p = findPlayer(id); p.Player.CheeredRooms ||= [];
  const room = findRoom(req.params.roomId);
  if (!p.Player.CheeredRooms.map(Number).includes(Number(req.params.roomId))) {
    p.Player.CheeredRooms.push(Number(req.params.roomId));
    if (room) room.Stats.CheerCount = (room.Stats.CheerCount || 0) + 1;
  }
  saveDb(); sendJson(res, 200, { Cheered: true });
});
del('/roomserver/rooms/:roomId/interactionby/me/cheer', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const p = findPlayer(id); p.Player.CheeredRooms = (p.Player.CheeredRooms || []).filter(x => Number(x) !== Number(req.params.roomId));
  saveDb(); sendJson(res, 200, { Cheered: false });
});
get('/roomserver/rooms/:roomId/subrooms/:subRoomId/saves', (req, res) => {
  const roomId = Number(req.params.roomId), subRoomId = Number(req.params.subRoomId);
  const saves = db.subRoomSaves.filter(s => Number(s.RoomId) === roomId && Number(s.SubRoomId) === subRoomId);
  sendJson(res, 200, { Results: saves, TotalResults: saves.length });
});
post('/roomserver/rooms/:roomId/subrooms/:subRoomId/data', (req, res) => {
  const room = findRoom(req.params.roomId); if (!room) return notFound(res);
  const sub = room.SubRooms?.find(s => Number(s.SubRoomId) === Number(req.params.subRoomId)); if (!sub) return notFound(res);
  const playerId = getAuthId(req);
  const body = req.body || {};
  if (body.RoomData?.Filename) room.DataBlob = body.RoomData.Filename;
  if (body.SubRoomData?.Filename) sub.DataBlob = body.SubRoomData.Filename;
  room.PersistenceVersion = Number(body.PersistenceVersion || room.PersistenceVersion || 0);
  if (playerId != null) sub.SavedByAccountId = playerId;
  const save = {
    SubRoomDataSaveId: db.nextSubRoomSaveId++, RoomId: room.RoomId, SubRoomId: sub.SubRoomId,
    DataBlob: body.SubRoomData?.Filename || null, DataBlobHash: body.SubRoomData?.Hash || null,
    ReferencedUnityAssetIds: [], UnitySubAssets: [], ReferencedUnityAssets: [],
    PersistenceVersion: room.PersistenceVersion, OMVersion: 0, UgcSubVersion: room.PersistenceVersion,
    SavedByAccountId: playerId, SavedOnPlatform: 1, SavedOnDeviceClass: 5,
    Description: body.Description || '', Tags: [], ModerationState: 0, CreatedAt: nowIso()
  };
  db.subRoomSaves.push(save);
  saveDb();
  sendJson(res, 200, { success: true, error: '', value: room });
});

get('/match/player', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const ids = getQueryArray(req.urlObj, 'id');
  sendJson(res, 200, ids.map(pid => findPlayer(pid)?.Player?.PlayerExtra?.Heartbeat || defaultHeartbeat(pid)));
});
post('/match/player/login', (req, res) => sendJson(res, 200, {}));
post('/match/player/exclusivelogin', (req, res) => sendJson(res, 200, {}));
post('/match/player/logout', (req, res) => sendJson(res, 200, {}));
post('/match/player/heartbeat', (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, updateHeartbeat(id)); });
post('/match/matchmake/none', (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, findPlayer(id)?.Player?.PlayerExtra?.Heartbeat || defaultHeartbeat(id)); });
post('/match/matchmake/dorm', (req, res) => { const id = authRequired(req, res); if (id != null) sendJson(res, 200, createDormInstance(id)); });
post('/match/matchmake/room/:roomId', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const room = findRoom(req.params.roomId); if (room) room.Stats.VisitCount = (room.Stats.VisitCount || 0) + 1;
  const p = findPlayer(id); p.Player.RoomVisits ||= [];
  let visit = p.Player.RoomVisits.find(v => Number(v.RoomId) === Number(req.params.roomId));
  if (!visit) p.Player.RoomVisits.push({ RoomId: Number(req.params.roomId), LastVisitedAt: nowIso() }); else visit.LastVisitedAt = nowIso();
  saveDb();
  sendJson(res, 200, createRoomInstance(id, req.params.roomId, req.urlObj.searchParams.get('subRoomId')));
});
post('/match/matchmake/room/:roomId/:subRoomId', (req, res) => {
  const id = authRequired(req, res); if (id != null) sendJson(res, 200, createRoomInstance(id, req.params.roomId, req.params.subRoomId));
});

post('/api/inventions/v6/save', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const body = req.body || {};
  if (!body.name && !body.Name) return sendText(res, 400, 'Invalid request');
  const inv = {
    InventionId: db.nextInventionId++, Name: body.name || body.Name, Description: body.description || body.Description || '',
    ImageName: body.imageName || body.ImageName || '', CreatorPlayerId: id, CreatedAt: nowIso(), ModifiedAt: nowIso(),
    CurrentVersionNumber: 1, ReplicationId: body.replicationId || body.ReplicationId || uuid(), Price: Number(body.price || 0),
    AllowTrial: Boolean(body.allowTrial), HideFromPlayer: Boolean(body.hideFromPlayer), GeneralPermission: Number(body.generalPermission || 0), CreatorPermission: Number(body.creatorPermission || 0),
    CheerCount: 0, NumDownloads: 0, NumPlayersHaveUsedInRoom: 0, IsAGInvention: false, IsCertifiedInvention: false, IsPublished: Boolean(body.isPublished), Tags: []
  };
  db.inventions.push(inv); saveDb();
  sendJson(res, 200, { Status: 0, InventionId: inv.InventionId, CurrentVersionNumber: inv.CurrentVersionNumber, ReplicationId: inv.ReplicationId, value: inventionData(inv) });
});
get('/api/inventions/v1/details', (req, res) => {
  const inv = db.inventions.find(i => Number(i.InventionId) === Number(req.urlObj.searchParams.get('inventionId')));
  inv ? sendJson(res, 200, { Tags: inv.Tags || [] }) : notFound(res);
});
get('/api/inventions/v2/batch', (req, res) => {
  const ids = getQueryArray(req.urlObj, 'id');
  sendJson(res, 200, db.inventions.filter(i => ids.includes(Number(i.InventionId))).map(inventionData));
});
get('/api/inventions/v2/mine', (req, res) => {
  const id = authRequired(req, res); if (id != null) sendJson(res, 200, db.inventions.filter(i => Number(i.CreatorPlayerId) === id).map(inventionData));
});
get('/api/inventions/v1/fulllineageowner', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const inv = db.inventions.find(i => Number(i.InventionId) === Number(req.urlObj.searchParams.get('id')));
  inv ? sendJson(res, 200, Number(inv.CreatorPlayerId) === id) : notFound(res);
});
post('/api/inventions/v1/settags', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const inv = db.inventions.find(i => Number(i.InventionId) === Number(req.body.InventionId || req.body.inventionId));
  if (!inv) return notFound(res);
  inv.Tags = req.body.Tags || req.body.tags || [];
  saveDb(); sendJson(res, 200, { Result: 0 });
});
get('/api/inventions/v1/delete', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const idx = db.inventions.findIndex(i => Number(i.InventionId) === Number(req.urlObj.searchParams.get('inventionId')));
  if (idx < 0) return notFound(res);
  if (Number(db.inventions[idx].CreatorPlayerId) !== id) return forbidden(res);
  db.inventions.splice(idx, 1); saveDb(); sendJson(res, 200, { success: true });
});
get('/api/inventions/v1/update', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const inv = db.inventions.find(i => Number(i.InventionId) === Number(req.urlObj.searchParams.get('inventionId')));
  if (!inv) return notFound(res);
  if (Number(inv.CreatorPlayerId) !== id) return forbidden(res);
  const q = req.urlObj.searchParams;
  for (const [key, prop] of [['name','Name'], ['description','Description'], ['imageName','ImageName']]) if (q.has(key)) inv[prop] = q.get(key);
  for (const [key, prop] of [['price','Price'], ['generalPermission','GeneralPermission'], ['creatorPermission','CreatorPermission']]) if (q.has(key)) inv[prop] = Number(q.get(key));
  for (const [key, prop] of [['isPublished','IsPublished'], ['allowTrial','AllowTrial'], ['hideFromPlayer','HideFromPlayer']]) if (q.has(key)) inv[prop] = q.get(key) === 'true';
  inv.ModifiedAt = nowIso(); saveDb(); sendJson(res, 200, inventionData(inv));
});
get('/api/inventions/v1/version', (req, res) => {
  const inv = db.inventions.find(i => Number(i.InventionId) === Number(req.urlObj.searchParams.get('inventionId')));
  inv ? sendJson(res, 200, { InventionId: inv.InventionId, VersionNumber: Number(req.urlObj.searchParams.get('version') || inv.CurrentVersionNumber || 1), ReplicationId: inv.ReplicationId }) : notFound(res);
});

post('/api/playerevents/v2', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const body = req.body || {};
  if (!body.Name && !body.name) return sendText(res, 400, 'Invalid request');
  const ev = { EventId: db.nextEventId++, CreatorPlayerId: id, CreatedAt: nowIso(), ...body };
  db.events.push(ev); saveDb(); sendJson(res, 200, { Result: 0, Event: ev });
});
del('/api/playerevents/v2/delete/:eventId', (req, res) => {
  const id = authRequired(req, res); if (id == null) return;
  const before = db.events.length;
  db.events = db.events.filter(e => !(Number(e.EventId) === Number(req.params.eventId) && Number(e.CreatorPlayerId) === id));
  saveDb(); sendJson(res, 200, { success: db.events.length !== before });
});

get('/imageserver/*img_path', (req, res) => {
  const img = decodeURIComponent(req.params.img_path || '').replace(/^\/+/, '');
  res.setHeader('content-signature', 'key-id=KEY:RSA:p1.rec.net; data=local-node-port');
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('cache-control', 'public, max-age=14400');
  const file = findFileRecursive(path.join(DATA_DIR, 'Images'), img) || findFileRecursive(path.join(DATA_DIR, 'Images'), safeFileName(img));
  serveFile(res, file, safeFileName(img));
});

function cdnHandler(folder = '') {
  return (req, res) => {
    const fileName = safeFileName(req.params.fileName);
    const roots = [path.join(DATA_DIR, 'cdn', folder), path.join(DATA_DIR, 'cdn')];
    for (const root of roots) {
      const file = path.join(root, fileName);
      if (fs.existsSync(file)) return serveFile(res, file, fileName);
    }
    notFound(res);
  };
}
get('/cdn/data/:fileName', cdnHandler(''));
get('/cdn/invention/:fileName', cdnHandler(''));
get('/cdn/room/:fileName', cdnHandler(''));
get('/cdn/video/:fileName', cdnHandler('video'));

get('/api/playerdb/players', (req, res) => {
  const search = String(req.urlObj.searchParams.get('search') || '').toLowerCase();
  const skip = Number(req.urlObj.searchParams.get('skip') || 0);
  const take = Number(req.urlObj.searchParams.get('take') || 50);
  let players = db.players;
  if (search) players = players.filter(p => String(p.Player?.Username || '').toLowerCase().includes(search) || String(p.Player?.DisplayName || '').toLowerCase().includes(search));
  sendJson(res, 200, { Results: players.slice(skip, skip + take), TotalResults: players.length });
});
get('/api/playerdb/player/:playerId', (req, res) => { const p = findPlayer(req.params.playerId); p ? sendJson(res, 200, p) : notFound(res); });
put('/api/playerdb/player/:playerId', (req, res) => {
  const p = findPlayer(req.params.playerId); if (!p) return notFound(res);
  Object.assign(p.Player, req.body || {}); saveDb(); sendJson(res, 200, p);
});
del('/api/playerdb/player/:playerId', (req, res) => {
  const before = db.players.length; db.players = db.players.filter(p => Number(p.PlayerId) !== Number(req.params.playerId)); saveDb(); sendJson(res, 200, { success: db.players.length !== before });
});
post('/api/playerdb/player/:playerId/authtoken', (req, res) => {
  const p = findPlayer(req.params.playerId); if (!p) return notFound(res);
  p.AuthToken = uuid(); saveDb(); sendJson(res, 200, { AuthToken: p.AuthToken });
});

get('/noti/hub/v1/negotiate', (req, res) => sendJson(res, 200, { connectionId: uuid(), availableTransports: [{ transport: 'WebSockets', transferFormats: ['Text'] }] }));
post('/noti/hub/v1/negotiate', (req, res) => sendJson(res, 200, { connectionId: uuid(), availableTransports: [{ transport: 'WebSockets', transferFormats: ['Text'] }] }));
get('/announcements/v2/mine/unread', (req, res) => sendJson(res, 200, []));

// Admin helpers, intentionally lightweight.
get('/admin/api/alldatabaseinfo', (req, res) => sendJson(res, 200, { players: db.players.length, rooms: db.rooms.length, inventions: db.inventions.length, events: db.events.length }));
del('/admin/accounts/:playerId', (req, res) => { db.players = db.players.filter(p => Number(p.PlayerId) !== Number(req.params.playerId)); saveDb(); sendJson(res, 200, { Success: true }); });
del('/admin/rooms/:roomId', (req, res) => { db.rooms = db.rooms.filter(r => Number(r.RoomId) !== Number(req.params.roomId)); saveDb(); sendJson(res, 200, { Success: true }); });

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') {
      return send(res, 204, '', {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'access-control-allow-headers': 'Content-Type, Authorization, Cache-Control'
      });
    }

    req.urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = req.urlObj.pathname.replace(/\/$/, '') || '/';
    const matched = routes.find(r => r.method === req.method && r.regex.test(pathname));
    if (!matched) return notFound(res);

    const match = matched.regex.exec(pathname);
    req.params = {};
    matched.keys.forEach((key, idx) => req.params[key] = match[idx + 1]);

    if (!['GET', 'HEAD'].includes(req.method)) {
      const body = await readBody(req);
      req.body = body.fields || {};
      req.files = body.files || [];
      req.rawBody = body.raw;
    } else {
      req.body = {};
      req.files = [];
      req.rawBody = '';
    }

    await matched.handler(req, res);
  } catch (err) {
    console.error(err);
    if (!res.headersSent) sendJson(res, 500, { error: 'Internal server error', detail: err.message });
  }
});

server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (!url.pathname.startsWith('/noti/hub/v1')) return socket.destroy();
  const key = req.headers['sec-websocket-key'];
  if (!key) return socket.destroy();
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '', ''
  ].join('\r\n'));
  const sendWs = obj => {
    const payload = Buffer.from(JSON.stringify(obj) + '\x1e');
    const header = payload.length < 126 ? Buffer.from([0x81, payload.length]) : Buffer.from([0x81, 126, payload.length >> 8, payload.length & 255]);
    socket.write(Buffer.concat([header, payload]));
  };
  sendWs({ protocol: 'json', version: 1 });
  const timer = setInterval(() => {
    if (!socket.destroyed) sendWs({ type: 6 });
  }, 10000);
  socket.on('data', () => sendWs({ type: 3, invocationId: '', result: null }));
  socket.on('close', () => clearInterval(timer));
  socket.on('error', () => clearInterval(timer));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`RecRoom Node server running on http://0.0.0.0:${PORT}`);
});
