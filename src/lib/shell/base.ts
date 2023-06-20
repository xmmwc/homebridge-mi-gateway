import fetch from 'node-fetch'
import { Telnet } from 'telnet-client'
import { logger } from '../logger'

export class TelnetShell {
    host: string
    private connected: boolean = false
    private connection: Telnet

    constructor (host: string) {
        this.host = host
        this.connection = new Telnet()
        this.connection.on('ready', () => {
            this.connected = true
        })
        this.connection.on('close', () => {
            this.connected = false
        })
    }

    async connect () {
        await this.connection.connect({
            host: this.host,
            port: 23,
            shellPrompt: '/ #',
            loginPrompt: 'login: ',
            username: 'root'
        })
    }

    async exec (command: string, timeout: number = 10000) {
        if (!this.connected) {
            throw new Error('Telnet shell not connected')
        }
        return await this.connection.exec(command, {
            timeout
        })
    }

    async writeFile (filename: string, raw: Buffer) {
        await this.exec(`> ${filename}`)
        let offset = 0
        const chunkSize = 700
        while (offset < raw.length) {
            const chunk = raw.slice(offset, offset + chunkSize)
            const base64Chunk = chunk.toString('base64')
            await this.exec(`echo -n ${base64Chunk} | base64 -d >> ${filename}`)
            offset += chunkSize
        }
    }

    async readFile (filename: string, asBase64 = false, tail = '') {
        let cmd = tail ? `tail -c ${tail} ${filename}` : `cat ${filename}`
        if (asBase64) {
            cmd += ' | base64'
        }
        const raw = await this.exec(cmd, 60000)
        return Buffer.from(raw).toString('base64')
    }

    async reboot () {
        await this.exec('reboot\n')
        await this.close()
    }

    async close () {
        await this.connection.end()
    }
}

const download = async (url: string) => {
    const res = await fetch(url)
    if (!res.ok) {
        throw new Error(`Download failed: ${res.statusText}`)
    }
    return await res.buffer()
}

export class OpenMiioShell extends TelnetShell {
    get openMiioMd5 (): string {
        throw new Error('NotImplemented')
    }

    get openMiioUrl (): string {
        throw new Error('NotImplemented')
    }

    async checkOpenMiio () {
        const cmd = `[ -x /data/openmiio_agent ] && md5sum /data/openmiio_agent`
        return (await this.exec(cmd)).indexOf(this.openMiioMd5) >= 0
    }

    async downloadOpenMiio () {
        await this.exec('killall openmiio_agent')
        const raw = await download(this.openMiioUrl)
        await this.writeFile('/data/openmiio_agent', raw)
        await this.exec('chmod +x /data/openmiio_agent')
    }

    async runOpenMiio () {
        await this.exec('/data/openmiio_agent miio mqtt cache central z3 --zigbee.tcp=8888 > /var/log/openmiio.log 2>&1 &')
    }
}

export class MultiModeShell extends OpenMiioShell {
}