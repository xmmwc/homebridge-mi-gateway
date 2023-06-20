import { logger } from '../src/lib/logger'
import { MiCloud } from '../src/lib/miCloud'
import user from './user.json'
import { expect } from 'chai'

describe('mi cloud', () => {
    const miCloud = new MiCloud()
    logger.enableDebug = true

    it('login', async () => {
        miCloud.setCountry('cn')
        await miCloud.login(user.username, user.password)
        expect(miCloud.serviceToken).to.be.an('string')
    })

    it('isLoggedIn', () => {
        expect(miCloud.isLoggedIn).to.be.true
    })

    it('get devices', async () => {
        const devices = await miCloud.getDevices()
        expect(devices).to.be.an('array')
    })

    it('get rooms',async ()=>{
        const rooms = await miCloud.getRooms()
        expect(rooms).to.be.an('array')
    })
})