import { h } from 'vue';
import DefaultTheme from 'vitepress/theme';
import SearchLink from './SearchLink.vue';
import NoScriptNavigation from './NoScriptNavigation.vue';
import ScreenshotPreview from './ScreenshotPreview.vue';
import './style.css';
export default {
  extends: DefaultTheme,
  Layout: () => h(DefaultTheme.Layout, null, {
    'nav-bar-content-before': () => h(SearchLink),
    'layout-top': () => h(NoScriptNavigation),
  }),
  enhanceApp({ app }) {
    app.component('ScreenshotPreview', ScreenshotPreview);
  },
};
