import * as randomString from 'randomstring'
import * as crypto from 'crypto'
import queryString from 'querystring'
import fetch from 'node-fetch'
import { logger } from './logger'
import { CryptRc4 } from '../util/cryptRc4'

export type MiCloudCountry = 'ru' | 'us' | 'tw' | 'sg' | 'cn' | 'de' | 'in' | 'i2'

export interface MiCloudDevice {
    did: string
    token: string
    longitude: string
    latitude: string
    name: string
    pid: string
    localip: string
    mac: string
    ssid: string
    bssid: string
    parent_id: string
    parent_model: string
    show_mode: number
    model: string
    adminFlag: number
    shareFlag: number
    permitLevel: number
    isOnline: boolean
    desc: string
    extra: Record<string, string | number>
    uid: number
    pd_id: number
    password: string
    p2p_id: string
    rssi: number
    family_id: number
    reset_flag: number
    method?: Record<string, string | number>[]
    event?: Record<string, string | number>
    prop?: Record<string, string | number>
}

const DEFAULT_REQUEST_TIMEOUT = 5000

export class MiCloud {
    username: string | null = null
    password: string | null = null
    userId: string | null = null
    ssecurity: string | null = null
    serviceToken: string | null = null

    private requestTimeout = DEFAULT_REQUEST_TIMEOUT
    private availableCountries: MiCloudCountry[] = ['ru', 'us', 'tw', 'sg', 'cn', 'de', 'in', 'i2']
    protected country: MiCloudCountry = 'cn'

    locale = 'en'

    private AGENT_ID = randomString.generate({
        length: 13,
        charset: 'ABCDEF'
    })
    private USERAGENT = `Android-7.1.1-1.0.0-ONEPLUS A3010-136-${this.AGENT_ID} APP/xiaomi.smarthome APPV/62830`
    private CLIENT_ID = randomString.generate({
        length: 6,
        charset: 'alphabetic',
        capitalization: 'uppercase'
    })

    get isLoggedIn () {
        return !!this.serviceToken
    }

    setCountry (country: MiCloudCountry) {
        if (!this.availableCountries.includes(country)) {
            throw new Error(`The country ${country} is not supported, list of supported countries is ${this.availableCountries.join(', ')}`)
        }
        this.country = country
    }

    async login (username: string, password: string) {
        if (this.isLoggedIn) {
            throw new Error(`You are already logged in with username ${username}. Login not required!`)
        }
        const { sign } = await this.loginStep1()
        const { ssecurity, userId, location } = await this.loginStep2(username, password, sign)
        const { serviceToken } = await this.loginStep3(sign.indexOf('http') === -1 ? location : sign)
        logger.debug('Login successful')
        this.username = username
        this.password = password
        this.userId = userId
        this.ssecurity = ssecurity
        this.serviceToken = serviceToken
    }

    logout () {
        if (!this.isLoggedIn) {
            throw new Error('You are not logged in')
        }
        logger.debug(`Logout from mi cloud for username ${this.username}`)
        this.username = null
        this.password = null
        this.ssecurity = null
        this.userId = null
        this.serviceToken = null
    }

    async getDevices (): Promise<MiCloudDevice[]> {
        const params = {
            getVirtualModel: true,
            getHuamiDevices: 1,
            get_split_device: false,
            support_smart_home: true
        }
        const data = await this.request('/home/device_list', params)
        return data.result.list
    }

    private parseJson<T = object> (data: string): T {
        if (data.indexOf('&&&START&&&') === 0) {
            data = data.replace('&&&START&&&', '')
        }
        return JSON.parse(data)
    }

    private async loginStep1 () {
        const url = 'https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true'
        const res = await fetch(url)

        const content = await res.text()
        const { statusText } = res
        logger.debug('login step 1')

        if (!res.ok) {
            throw new Error(`Response step 1 error with status ${statusText}`)
        }

        const data = this.parseJson<{ _sign?: string }>(content)

        if (!data._sign) {
            throw new Error('Login step 1 failed')
        }

        return {
            sign: data._sign
        }
    }

    private async loginStep2 (username: string, password: string, sign: string) {
        const formData = queryString.stringify({
            hash: crypto.createHash('md5').update(password).digest('hex').toUpperCase(),
            _json: 'true',
            sid: 'xiaomiio',
            callback: 'https://sts.api.io.mi.com/sts',
            qs: '%3Fsid%3Dxiaomiio%26_json%3Dtrue',
            _sign: sign,
            user: username
        })

        const url = 'https://account.xiaomi.com/pass/serviceLoginAuth2'
        const res = await fetch(url, {
            method: 'POST',
            body: formData,
            headers: {
                'User-Agent': this.USERAGENT,
                'Content-Type': 'application/x-www-form-urlencoded',
                Cookie: [
                    'sdkVersion=accountsdk-18.8.15',
                    `deviceId=${this.CLIENT_ID};`
                ].join('; '),
            }
        })
        const content = await res.text()
        const { statusText } = res
        logger.debug('Login step 2')

        if (!res.ok) {
            throw new Error(`Response step 2 error with status ${statusText}`)
        }

        const {
            ssecurity,
            userId,
            location,
            notificationUrl,
            desc
        } = this.parseJson<{
            ssecurity?: string
            userId: string
            location: string
            notificationUrl?: string
            desc?: string
        }>(content)

        if (!ssecurity && notificationUrl) {
            throw new Error(`Login step 2 failed: two factor required`)
        }

        if (!ssecurity || !userId || !location) {
            throw new Error(`Login step 2 failed, ${desc}`)
        }

        this.ssecurity = ssecurity
        this.userId = userId

        return {
            ssecurity,
            userId,
            location
        }
    }

    private async loginStep3 (location: string) {
        const url = location
        const res = await fetch(url)

        const content = await res.text()
        const { statusText } = res

        logger.debug('Login step 3')

        if (!res.ok) {
            throw new Error(`Response step 3 error with status ${statusText}`)
        }

        const headers = res.headers.raw()
        const cookies = headers['set-cookie']
        let serviceToken
        cookies.forEach(cookieStr => {
            const cookie = cookieStr.split('; ')[0]
            const idx = cookie.indexOf('=')
            const key = cookie.substr(0, idx)
            const value = cookie.substr(idx + 1, cookie.length).trim()
            if (key === 'serviceToken') {
                serviceToken = value
            }
        })
        if (!serviceToken) {
            throw new Error('Login step 3 failed')
        }
        return { serviceToken }
    }

    private getApiUrl (country: MiCloudCountry) {
        const trimLowerCountry = country.trim().toLowerCase()
        return `https://${trimLowerCountry === 'cn' ? '' : `${trimLowerCountry}.`}api.io.mi.com/app`
    }

    private generateNonce () {
        const buf = Buffer.allocUnsafe(12)
        buf.write(crypto.randomBytes(8).toString('hex'), 0, 'hex')
        buf.writeInt32BE(parseInt(`${Date.now() / 60000}`, 10), 8)
        return buf.toString('base64')
    }

    private signNonce (ssecret: string, nonce: string) {
        const s = Buffer.from(ssecret, 'base64')
        const n = Buffer.from(nonce, 'base64')
        return crypto.createHash('sha256').update(s).update(n).digest('base64')
    }

    private generateEncSignature (url: string, method: string, signedNonce: string, params: Record<string, string>) {
        const signatureArr: string[] = []
        signatureArr.push(method.toUpperCase())
        signatureArr.push(url.split('com')[1].replace('/app/', '/'))
        const paramKeys = Object.keys(params)
        paramKeys.sort()
        for (let i = 0, {
            length
        } = paramKeys; i < length; i++) {
            const key = paramKeys[i]
            signatureArr.push(`${key}=${params[key]}`)
        }
        signatureArr.push(signedNonce)
        const signatureStr = signatureArr.join('&')
        return crypto.createHash('sha1').update(signatureStr).digest('base64')
    }

    private generateRc4Body (url: string, signedNonce: string, nonce: string, params: Record<string, string>, ssecurity: string) {
        params['rc4_hash__'] = this.generateEncSignature(url, 'POST', signedNonce, params)
        for (const [key, value] of Object.entries(params)) {
            params[key] = this.encryptRc4(signedNonce, value)
        }
        params['signature'] = this.generateEncSignature(url, 'POST', signedNonce, params)
        params['ssecurity'] = ssecurity
        params['_nonce'] = nonce
        return params
    }

    private encryptRc4 (password: string, payload: string) {
        let k = Buffer.from(password, 'base64')
        let cipher = CryptRc4.create(k, 1024)
        return cipher.encode(payload)
    }

    private decryptRc4 (password: string, payload: string) {
        let k = Buffer.from(password, 'base64')
        let p = Buffer.from(payload, 'base64')
        let decipher = CryptRc4.create(k, 1024)
        return decipher.decode(payload)
    }

    private async request (path: string, data: object) {
        if (!this.isLoggedIn) {
            throw new Error('You are not logged in')
        }

        const url = this.getApiUrl(this.country) + path
        logger.debug(`Request url: ${url}`)
        const params = {
            data: JSON.stringify(data)
        }
        const nonce = this.generateNonce()
        const signedNonce = this.signNonce(this.ssecurity!, nonce)
        const body = this.generateRc4Body(url, signedNonce, nonce, params, this.ssecurity!)
        const abortController = new AbortController()
        setTimeout(() => {
            abortController.abort()
        }, this.requestTimeout)

        const res = await fetch(url, {
            method: 'POST',
            signal: abortController.signal,
            headers: {
                'User-Agent': this.USERAGENT,
                'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2',
                'Accept-Encoding': 'identity',
                'Content-Type': 'application/x-www-form-urlencoded',
                'MIOT-ENCRYPT-ALGORITHM': 'ENCRYPT-RC4',
                Cookie: [
                    'sdkVersion=accountsdk-18.8.15',
                    `deviceId=${this.CLIENT_ID}`,
                    `userId=${this.userId}`,
                    `yetAnotherServiceToken=${this.serviceToken}`,
                    `serviceToken=${this.serviceToken}`,
                    `locale=${this.locale}`,
                    'channel=MI_APP_STORE'
                ].join('; '),
            },
            body: queryString.stringify(body)
        })

        if (!res.ok) {
            throw new Error(`Request error with status ${res.status} ${res.statusText}`)
        }

        const responseText = await res.text()
        const decryptedText = this.decryptRc4(signedNonce, responseText)
        const json = JSON.parse(decryptedText)

        if (json && !json.result && !json.message && json.message.length > 0) {
            logger.debug(`No result in response from mi cloud! message: ${json.message}`)
        }

        return json
    }
}