<script setup lang="ts">
import { computed } from 'vue';
import { withBase } from 'vitepress';
import screenshots from '../../content/screenshots-data.json';
const sample = computed(() => screenshots.find(image => image.kind === 'GUI') || screenshots[0]);
</script>

<template>
  <section v-if="sample" class="screenshot-preview" aria-labelledby="screenshots-title">
    <div class="screenshot-intro">
      <p class="eyebrow">看看实际运行的样子</p>
      <h2 id="screenshots-title">先看界面，再开始连接</h2>
      <p>按自己的系统选择图形界面或命令行，跟着安装步骤完成第一次连接。</p>
      <a :href="withBase('/screenshots')">查看运行截图与操作示例 →</a>
    </div>
    <figure>
      <a :href="withBase('/screenshots')"><img :src="withBase(sample.image)" :alt="`${sample.platform} ${sample.title}`" :width="sample.width" :height="sample.height" loading="lazy" /></a>
      <figcaption>{{ sample.platform }} · {{ sample.kind === 'GUI' ? '图形界面' : '命令行' }} · 实际运行截图</figcaption>
    </figure>
  </section>
</template>
