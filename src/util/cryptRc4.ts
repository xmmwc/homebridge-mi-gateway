export class CryptRc4 {
    private ksa: number[] = []
    private idx: number = 0
    private jdx: number = 0

    constructor (key: Buffer, rounds: number) {
        this.setKey(key || '', rounds)
    }

    setKey (key: Buffer, rounds: number) {
        let ksa = Array.from({
            length: 256
        }, (v, k) => k)
        let i = 0
        let j = 0

        if (key.length > 0) {
            let bufKey = Buffer.from(key)
            let len = bufKey.length

            for (i = 0; i < 256; i++) {
                j = (j + ksa[i] + bufKey[i % len]) & 255;
                [ksa[i], ksa[j]] = [ksa[j], ksa[i]]
            }

            i = j = 0

            for (let c = 0; c < rounds; c++) {
                i = (i + 1) & 255
                j = (j + ksa[i]) & 255;
                [ksa[i], ksa[j]] = [ksa[j], ksa[i]]
            }
        }

        this.ksa = ksa
        this.idx = i
        this.jdx = j
    }

    crypt (data: Buffer) {
        let ksa = (this.ksa || []).slice(0) // Array copy
        let i = this.idx || 0
        let j = this.jdx || 0

        let len = data.length
        let out = Buffer.alloc(len)

        for (let c = 0; c < len; c++) {
            i = (i + 1) & 255
            j = (j + ksa[i]) & 255;
            [ksa[i], ksa[j]] = [ksa[j], ksa[i]]

            out[c] = data[c] ^ ksa[(ksa[i] + ksa[j]) & 255]
        }

        return out
    }

    encode (data: string) {
        return this.crypt(Buffer.from(data, 'utf8')).toString('base64')
    }

    decode (data: string) {
        return this.crypt(Buffer.from(data, 'base64')).toString('utf8')
    }

    static create (key: Buffer, rounds: number) {
        return new CryptRc4(key, rounds)
    }

}