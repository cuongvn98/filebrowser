<template>
  <button @click="copy" :aria-label="$t('buttons.copyPNGLink')" :title="$t('buttons.copyPNGLink')" class="action"
          id="copy-png-link-button">
    <i class="material-icons">content_copy</i>
    <span>{{ $t('buttons.copyPNGLink') }}</span>
  </button>
</template>

<script>
import {mapState} from "vuex";

export default {
  name: 'copy-png-link-button',
  computed: mapState(['req', 'selected']),
  methods: {
    copy: function (e) {
      e.preventDefault()
      if (Array.isArray(this.selected) && this.selected.length !== 0) {
        const selected = this.selected[0]
        const path = this.req.items[selected].url.slice(6)
        const original = window.location.origin
        const url = original + '/download' + path
        this.$copyText(url).then(() => {
          this.$showSuccess("Success");
        });
      }
    }
  }
}
</script>
