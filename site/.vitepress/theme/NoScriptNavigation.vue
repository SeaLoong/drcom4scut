<script setup lang="ts">
import { withBase } from 'vitepress';
</script>

<template>
  <noscript>
    <nav class="static-navigation" aria-label="帮助快捷导航">
      <a :href="withBase('/guide/download')">下载</a>
      <a :href="withBase('/help')">完整帮助目录</a>
      <a :href="withBase('/screenshots')">运行截图</a>
      <a :href="withBase('/guide/troubleshooting')">连接排障</a>
    </nav>
  </noscript>
</template>
