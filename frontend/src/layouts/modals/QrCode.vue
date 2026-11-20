<template>
  <v-dialog
    transition="dialog-bottom-transition"
    width="400"
  >
    <v-card
      id="qrcode-modal"
      class="rounded-lg"
      :loading="loading"
    >
      <v-card-title>
        <v-row>
          <v-col>QrCode</v-col>
          <v-spacer />
          <v-col cols="auto">
            <v-icon
              :aria-label="$t('actions.close')"
              icon="mdi-close-box"
              @click="$emit('close')"
            />
          </v-col>
        </v-row>
      </v-card-title>
      <v-divider />
      <v-skeleton-loader
        v-if="loading"
        class="mx-auto border"
        width="80%"
        type="text, image, divider, text, image"
      />
      <v-card-text
        style="overflow-y: auto; padding: 0"
        :hidden="loading"
      >
        <v-tabs
          v-model="tab"
          density="compact"
          fixed-tabs
          align-tabs="center"
        >
          <v-tab value="sub">
            {{ $t('setting.sub') }}
          </v-tab>
          <v-tab value="link">
            {{ $t('client.links') }}
          </v-tab>
        </v-tabs>
        <v-window
          v-model="tab"
          style="margin-top: 10px;"
        >
          <v-window-item value="sub">
            <v-row>
              <v-col style="text-align: center;">
                <v-chip>{{ $t('setting.sub') }}</v-chip><br>
                <QrcodeVue
                  :value="clientSub"
                  :size="size"
                  :margin="1"
                  style="border-radius: 1rem; cursor: copy;"
                  @click="copyToClipboard(clientSub)"
                />
              </v-col>
            </v-row>
            <v-row>
              <v-col style="text-align: center;">
                <v-chip>{{ $t('setting.jsonSub') }}</v-chip><br>
                <QrcodeVue
                  :value="jsonSub"
                  :size="size"
                  :margin="1"
                  style="border-radius: 1rem; cursor: copy;"
                  @click="copyToClipboard(jsonSub)"
                />
              </v-col>
            </v-row>
            <v-row>
              <v-col style="text-align: center;">
                <v-chip>{{ $t('setting.clashSub') }}</v-chip><br>
                <QrcodeVue
                  :value="clashSub"
                  :size="size"
                  :margin="1"
                  style="border-radius: 1rem; cursor: copy;"
                  @click="copyToClipboard(clashSub)"
                />
              </v-col>
            </v-row>
            <v-row>
              <v-col style="text-align: center;">
                <v-chip>HAPP (scan only)</v-chip><br>
                <QrcodeVue
                  :value="happ"
                  :size="size"
                  :margin="1"
                  style="border-radius: .8rem; cursor: not-allowed;"
                />
              </v-col>
            </v-row>
            <v-row>
              <v-col style="text-align: center;">
                <v-chip>SING-BOX (scan only)</v-chip><br>
                <QrcodeVue
                  :value="singbox"
                  :size="size"
                  :margin="1"
                  style="border-radius: .8rem; cursor: not-allowed;"
                />
              </v-col>
            </v-row>
          </v-window-item>
          <v-window-item value="link">
            <v-row
              v-for="(l, index) in clientLinks"
              :key="index"
            >
              <v-col style="text-align: center;">
                <v-chip>{{ l.remark?? $t('client.' + l.type) }}</v-chip><br>
                <QrcodeVue
                  :value="l.uri"
                  :size="size"
                  :margin="1"
                  style="border-radius: .5rem; cursor: copy;"
                  @click="copyToClipboard(l.uri)"
                />
              </v-col>
            </v-row>
            <v-row
              v-for="(l, index) in l2tpLinks"
              :key="'l2tp-' + index"
            >
              <v-col style="text-align: center;">
                <v-chip>{{ l.remark }}</v-chip><br>
                <QrcodeVue
                  :value="l.uri"
                  :size="size"
                  :margin="1"
                  :aria-label="$t('l2tp.copyConnectionInfo')"
                  role="button"
                  tabindex="0"
                  style="border-radius: .5rem; cursor: copy;"
                  @click="copyToClipboard(l.uri)"
                  @keydown.enter.prevent="copyToClipboard(l.uri)"
                  @keydown.space.prevent="copyToClipboard(l.uri)"
                />
              </v-col>
            </v-row>
          </v-window-item>
        </v-window>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

<script lang="ts">
import QrcodeVue from 'qrcode.vue'
import Data from '@/store/modules/data'
import Clipboard from 'clipboard'
import { i18n } from '@/locales'
import { push } from 'notivue'
import { Client } from '@/types/clients'
import type { Inbound } from '@/types/inbounds'
import { l2tpConnectionLinks } from '@/plugins/l2tpConnection'
import { subscriptionURL, happSubscriptionURL } from '@/plugins/subscription'

export default {
  components: { QrcodeVue },
  props: {
    id: { type: Number, required: true },
    visible: { type: Boolean, required: true },
  },
  emits: ['close'],
  data() {
    return {
      tab: "sub",
      client: <Client>{},
      inbounds: [] as Inbound[],
      loadVersion: 0,
      loading: false,
    }
  },
  computed: {
    clientSub() {
      return Data().subURI + this.client.name
    },
    jsonSub() {
      return subscriptionURL(this.clientSub, 'json')
    },
    clashSub() {
      return subscriptionURL(this.clientSub, 'clash')
    },
    happ() {
      return happSubscriptionURL(this.clientSub)
    },
    singbox() {
      return "sing-box://import-remote-profile?url=" + encodeURIComponent(this.jsonSub) + "#" + this.client.name
    },
    clientLinks() {
      return this.client.links?? []
    },
    l2tpLinks() {
      return l2tpConnectionLinks(this.client, this.inbounds, key => this.$t(key))
    },
    size() {
      if (window.innerWidth > 380) return 300
      if (window.innerWidth > 330) return 280
      return 250
    }
  },
  watch: {
    visible(v) {
      if (v) {
        this.tab = "sub"
        this.load()
      } else {
        this.loadVersion++
        this.client = <Client>{}
        this.inbounds = []
      }
    },
  },
  methods: {
    async load() {
      const version = ++this.loadVersion
      this.loading = true
      this.client = <Client>{}
      this.inbounds = []
      try {
        const client = await Data().loadClients(this.$props.id)
        if (version !== this.loadVersion) return
        this.client = client
        // An empty ID list would fetch every inbound; only fetch bindings.
        if (client.inbounds?.length) {
          const inbounds = await Data().loadInbounds(client.inbounds)
          if (version === this.loadVersion) this.inbounds = inbounds
        }
      } finally {
        if (version === this.loadVersion) this.loading = false
      }
    },
    copyToClipboard(txt:string) {
      const hiddenButton = document.createElement('button')
      hiddenButton.className = 'clipboard-btn'
      document.body.appendChild(hiddenButton)

      const clipboard = new Clipboard('.clipboard-btn', {
        text: () => txt,
        container: document.getElementById('qrcode-modal')?? undefined
      });

      clipboard.on('success', () => {
        clipboard.destroy()
        push.success({
          message: i18n.global.t('success') + ": " + i18n.global.t('copyToClipboard'),
          duration: 5000,
        })
      })

      clipboard.on('error', () => {
        clipboard.destroy()
        push.error({
          message: i18n.global.t('failed') + ": " + i18n.global.t('copyToClipboard'),
          duration: 5000,
        })
      })

      // Perform click on hidden button to trigger copy
      hiddenButton.click()
      document.body.removeChild(hiddenButton)
    }
  }
}
</script>
