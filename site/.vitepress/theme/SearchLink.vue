<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue';
import { withBase } from 'vitepress';

// The href works before hydration and when JavaScript is unavailable. Once the
// theme is ready, open its official local-search dialog without changing engines.
// vp-raw exempts this link from VitePress's capture-phase navigation handler.
const opening = ref(false);
const ready = ref(false);
onMounted(() => { ready.value = true; });
let observer: MutationObserver | undefined;
let timeout: ReturnType<typeof setTimeout> | undefined;
function clearPending() {
  observer?.disconnect();
  observer = undefined;
  if (timeout) clearTimeout(timeout);
  timeout = undefined;
  opening.value = false;
}
function openSearch(event: MouseEvent) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const trigger = document.querySelector<HTMLButtonElement>('.VPNavBarSearch #local-search button');
  if (!trigger) return;
  event.preventDefault();
  event.stopPropagation();
  if (opening.value) return;
  opening.value = true;
  observer = new MutationObserver(() => {
    if (document.querySelector('.VPLocalSearchBox input')) clearPending();
  });
  observer.observe(document.body, { childList: true, subtree: true });
  timeout = setTimeout(() => {
    clearPending();
    window.location.assign(withBase('/help'));
  }, 5000);
  trigger.click();
}
onBeforeUnmount(clearPending);
</script>

<template>
  <a class="site-search-link vp-raw" :href="withBase('/help')" aria-label="搜索帮助文档" :data-search-ready="ready" @click="openSearch">
    <svg aria-hidden="true" viewBox="0 0 24 24" width="18" height="18"><circle cx="10.7" cy="10.7" r="6.7" /><path d="m16 16 4 4" /></svg>
    <span>{{ opening ? '正在打开…' : '搜索帮助' }}</span>
    <kbd aria-hidden="true">⌘ / Ctrl K</kbd>
  </a>
</template>
