import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createPinia, setActivePinia } from 'pinia'
import { i18n } from '@/locales'
import HttpUtils from '@/plugins/httputil'
import type { iTls, oTls } from '@/types/tls'
import type { Hysteria2 as Hysteria2Options } from '@/types/inbounds'
import type { WireGuard } from '@/types/endpoints'
import Ech from './tls/Ech.vue'
import Hysteria2 from './protocols/Hysteria2.vue'
import Wireguard from './protocols/Wireguard.vue'

vi.mock('@/plugins/httputil', () => ({ default: { get: vi.fn(), post: vi.fn() } }))
vi.mock('notivue', () => ({ push: { error: vi.fn(), success: vi.fn() } }))
const vuetify = createVuetify({ components, directives })
const global = { plugins: [vuetify, i18n] }

describe('upstream 1.6.8 form contracts', () => {
  beforeEach(() => { vi.clearAllMocks() })
  it('stores a blank WireGuard listen port as the number zero', async () => {
    setActivePinia(createPinia())
    const data = { type: 'wireguard', listen_port: 51820, address: [], private_key: '', peers: [], ext: { public_key: '', keys: [] } } as unknown as WireGuard
    const wrapper = mount(Wireguard, { props: { data }, global })
    const field = wrapper.findAllComponents({ name: 'VTextField' }).find(f => f.props('label') === i18n.global.t('in.port'))
    expect(field).toBeDefined()
    field!.vm.$emit('update:modelValue', '')
    await flushPromises()
    expect(data.listen_port).toBe(0)
    field!.vm.$emit('update:modelValue', '65536')
    await flushPromises()
    expect(data.listen_port).toBe(0)
    wrapper.unmount()
  })

  it('clears Gecko-only sizes when the obfs type changes', async () => {
    setActivePinia(createPinia())
    const data = { type: 'hysteria2', obfs: { type: 'gecko', password: 'test', min_packet_size: 600, max_packet_size: 1100 } } as unknown as Hysteria2Options
    const wrapper = mount(Hysteria2, { props: { data, direction: 'out' }, global })
    const picker = wrapper.findAllComponents({ name: 'VSelect' }).find(f => Array.isArray(f.props('items')) && f.props('items').includes('gecko'))
    expect(picker).toBeDefined()
    picker!.vm.$emit('update:modelValue', 'salamander')
    await flushPromises()
    expect(data.obfs).toEqual({ type: 'salamander', password: 'test' })
    wrapper.unmount()
  })

  it('keeps existing ECH key/path/config/query when generation answers with an error array', async () => {
    setActivePinia(createPinia())
    vi.mocked(HttpUtils.get).mockResolvedValueOnce({ success: true, msg: '', obj: ['Failed to generate ECH keypair: ', 'failure'] })
    const server: iTls = { ech: { enabled: true, key_path: '/existing.key' } }
    const client: oTls = { ech: { enabled: true, config: ['old-config'], query_server_name: 'lookup.example' } }
    const before = JSON.stringify({ server, client })
    const wrapper = mount(Ech, { props: { iTls: server, oTls: client }, global })
    const generate = wrapper.findAllComponents({ name: 'VBtn' }).find(b => b.props('icon') === 'mdi-key-star')
    await generate!.trigger('click')
    const name = wrapper.findAllComponents({ name: 'VTextField' }).find(f => f.props('label') === i18n.global.t('tls.echPublicName'))
    name!.vm.$emit('update:modelValue', ' public.example ')
    await flushPromises()
    await name!.find('input').trigger('keyup', { key: 'Enter' })
    await flushPromises()
    expect(HttpUtils.get).toHaveBeenCalledWith('api/keypairs', { k: 'ech', o: 'public.example' })
    expect(JSON.stringify({ server, client })).toBe(before)
    wrapper.unmount()
  })
})
