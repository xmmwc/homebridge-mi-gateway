import debug from 'debug'

export class Logger {
    enableDebug = false
    log = debug('[mi-gateway]')

    debug (message: string, ...args: any[]) {
        if (this.enableDebug) {
            this.log(message, ...args)
        }
    }
}

export const logger = new Logger()