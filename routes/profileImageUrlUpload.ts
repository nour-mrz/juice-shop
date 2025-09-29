

import fs from 'node:fs'
import dns from 'node:dns'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { URL } from 'node:url'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// ---------- CONFIG ----------
const ALLOWED_IMAGE_DOMAINS = [
  'images.unsplash.com',
  'gravatar.com',
  'via.placeholder.com',
  'i.imgur.com'
]

const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif', 'image/svg+xml']
const FETCH_TIMEOUT_MS = 5000
const MAX_CONTENT_LENGTH_BYTES = 5 * 1024 * 1024 // 5 MB max (ajuste si besoin)

// ---------- HELPERS ----------

function isProbablyPrivateIp(ip: string) {
  // simple IPv4/IPv6 checks (covers main private ranges)
  if (!ip) return false
  if (ip === '::1' || ip === '::ffff:127.0.0.1') return true
  if (/^127\./.test(ip)) return true
  if (/^10\./.test(ip)) return true
  if (/^192\.168\./.test(ip)) return true
  // 172.16.0.0 - 172.31.255.255
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true
  // IPv6 ULA fc00::/7
  if (/^fc/i.test(ip) || /^fe80:/i.test(ip)) return true
  return false
}

async function resolvesToPrivateIp(hostname: string): Promise<boolean> {
  try {
    const addrs = await dns.promises.lookup(hostname, { all: true })
    for (const a of addrs) {
      if (isProbablyPrivateIp(a.address)) return true
    }
    return false
  } catch (err) {
    // Si DNS échoue, on considère non privé (mais on renverra une erreur plus loin)
    return false
  }
}

function hostnameIsAllowed(hostname: string) {
  const h = hostname.toLowerCase()
  // empêche hostnames évidents internes
  const blockedPatterns = ['localhost', '.local', '.internal']
  if (blockedPatterns.some(p => h.includes(p))) return false

  // check whitelist (autoriser les sous-domaines aussi)
  return ALLOWED_IMAGE_DOMAINS.some(d => h === d || h.endsWith(`.${d}`))
}

function fetchWithTimeout(url: string, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), timeoutMs)
  return fetch(url, { redirect: 'error', signal: controller.signal, headers: { 'User-Agent': 'JuiceShop-App' } })
    .finally(() => clearTimeout(id))
}

// ---------- MIDDLEWARE ----------

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl === undefined) {
      // pas d'URL fournie -> comportement normal : rediriger vers profil
      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
      return
    }

    const urlStr = String(req.body.imageUrl).trim()

    // detect bug injection used for challenge (conserve le comportement du challenge)
    if (urlStr.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) {
      req.app.locals.abused_ssrf_bug = true
    }

    // Vérifier utilisateur connecté
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      // Bloquer si non authentifié
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    // ---------------- Validation SSRF (format, protocole, hostname whitelist) ----------------
    let urlObj: URL
    try {
      urlObj = new URL(urlStr)
    } catch (err) {
      logger.warn(`Invalid image URL provided by user ${loggedInUser.data.id}: ${urlStr}`)
      return res.status(400).json({ error: 'URL invalide' })
    }

    // bloquer protocoles non-http(s)
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return res.status(400).json({ error: 'Protocole non autorisé' })
    }

    // pas d'identifiants dans l'URL (ex: http://user:pass@host)
    if (urlObj.username || urlObj.password) {
      return res.status(400).json({ error: 'URL contenant des credentials interdite' })
    }

    // hostname whitelist + blocage de patterns internes
    const hostname = urlObj.hostname
    if (!hostnameIsAllowed(hostname)) {
      logger.warn(`Blocked image domain for user ${loggedInUser.data.id}: ${hostname}`)
      return res.status(400).json({ error: 'Domaine non autorisé pour les images' })
    }

    // DNS check pour éviter DNS rebinding -> rejeter si resolv vers IP privée
    const resolvesPrivate = await resolvesToPrivateIp(hostname)
    if (resolvesPrivate) {
      logger.warn(`Blocked image URL resolving to private IP for user ${loggedInUser.data.id}: ${hostname}`)
      return res.status(400).json({ error: 'Résolution DNS vers IP interne interdite' })
    }

    // ---------------- Fetch sécurisé ----------------
    let response: Response
    try {
      response = await fetchWithTimeout(urlStr)
    } catch (err: any) {
      if (err.name === 'AbortError') {
        logger.error(`Timeout lors du téléchargement de l'image: ${urlStr}`)
        return res.status(408).json({ error: 'Timeout lors du téléchargement de l\'image' })
      }
      logger.warn(`Error fetching image for user ${loggedInUser.data.id}: ${utils.getErrorMessage(err)}`)
      return res.status(400).json({ error: 'Impossible de récupérer l\'image' })
    }

    if (!response.ok || !response.body) {
      logger.warn(`Image fetch returned non-OK for user ${loggedInUser.data.id}: ${urlStr} status=${response.status}`)
      return res.status(400).json({ error: 'URL retournée non OK ou corps vide' })
    }

    // Verifier content-length (si présent)
    const contentLengthHeader = response.headers.get('content-length')
    if (contentLengthHeader) {
      const contentLength = parseInt(contentLengthHeader, 10)
      if (!Number.isNaN(contentLength) && contentLength > MAX_CONTENT_LENGTH_BYTES) {
        logger.warn(`Refused large image (${contentLength} bytes) for user ${loggedInUser.data.id}`)
        return res.status(400).json({ error: 'Fichier trop volumineux' })
      }
    }

    // Vérifier MIME type
    const contentType = response.headers.get('content-type') || ''
    if (!ALLOWED_MIME.some(m => contentType.includes(m))) {
      logger.warn(`Blocked image with disallowed MIME for user ${loggedInUser.data.id}: ${contentType}`)
      return res.status(400).json({ error: 'Type de fichier non autorisé' })
    }

    // Déterminer extension (fallback safe)
    const extFromUrl = urlStr.split('.').slice(-1)[0].toLowerCase()
    const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(extFromUrl) ? extFromUrl : (contentType.includes('svg') ? 'svg' : 'jpg')

    // Ecrire le fichier de manière sûre
    try {
      const outPath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
      const fileStream = fs.createWriteStream(outPath, { flags: 'w' })
      await finished(Readable.fromWeb(response.body as any).pipe(fileStream))

      // Mettre à jour la DB
      await UserModel.findByPk(loggedInUser.data.id)
        .then(async (user: UserModel | null) => {
          return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        })
        .catch((error: Error) => { throw error })

      logger.info(`Profile image saved for user ${loggedInUser.data.id} from ${hostname}`)
    } catch (error: any) {
      logger.error(`Error saving profile image for user ${loggedInUser.data.id}: ${utils.getErrorMessage(error)}`)
      return res.status(500).json({ error: 'Erreur lors de la sauvegarde de l\'image' })
    }

    // Redirection finale (comportement inchangé)
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}


