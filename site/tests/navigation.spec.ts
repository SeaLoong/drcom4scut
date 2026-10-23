import { expect, test } from '@playwright/test';

for (const width of [1440, 390]) {
  test(`search opens, finds Chinese text, follows results and closes at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('./');
    const trigger = page.getByRole('link', { name: '搜索帮助文档' });
    await expect(trigger).toHaveAttribute('data-search-ready', 'true');
    const origin = page.url();
    await trigger.click();
    const dialog = page.locator('.VPLocalSearchBox');
    await expect(dialog.locator('input')).toBeFocused();
    await expect(page).toHaveURL(origin);
    await dialog.locator('input').fill('网卡');
    const first = dialog.locator('a.result').first();
    await expect(first).toBeVisible();
    const destination = await first.getAttribute('href');
    await first.click();
    await expect(dialog).toHaveCount(0);
    await expect.poll(() => decodeURI(page.url())).toContain(decodeURI(destination!));
    await expect(page.locator('h1')).toBeVisible();
    await trigger.click();
    await expect(dialog.locator('input')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await page.keyboard.press('Control+k');
    await expect(dialog.locator('input')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    expect(errors).toEqual([]);
  });
}

test('search has a useful destination if application scripts fail to load', async ({ page }) => {
  await page.route('**/assets/*.js', route => route.abort());
  await page.goto('./');
  await page.getByRole('link', { name: '搜索帮助文档' }).click();
  await expect(page).toHaveURL(/\/help$/);
  await expect(page.locator('h1')).toContainText('帮助中心');
  await expect(page.getByRole('link', { name: '下载、解压、安装 Npcap 和第一次连接' })).toBeVisible();
});

test('slow search module shows feedback and falls back to the full help directory', async ({ page }) => {
  await page.route('**/assets/chunks/VPLocalSearchBox*.js', async route => {
    await new Promise(resolve => setTimeout(resolve, 7000));
    await route.abort();
  });
  await page.goto('./');
  const trigger = page.getByRole('link', { name: '搜索帮助文档' });
  await expect(trigger).toHaveAttribute('data-search-ready', 'true');
  await trigger.click();
  await expect(trigger).toContainText('正在打开');
  await expect(page).toHaveURL(/\/help$/);
});

test('mobile menu, sidebar and theme remain usable after navigation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('./');
  await page.locator('.VPNavBarHamburger').click();
  await page.locator('.VPNavScreen').getByRole('link', { name: '帮助中心', exact: true }).click();
  await expect(page).toHaveURL(/\/help$/);
  await page.getByRole('button', { name: '帮助目录', exact: true }).click();
  await page.locator('.VPSidebar').getByRole('link', { name: 'Windows 图形界面', exact: true }).click();
  await expect(page).toHaveURL(/\/gui\/windows$/);
  await page.locator('.VPNavBarHamburger').click();
  await page.locator('.VPNavScreen .VPSwitchAppearance').click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.reload();
  await expect(page.locator('html')).toHaveClass(/dark/);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});

test('deep links reload and imported README pages render without repository badge rows', async ({ page }) => {
  await page.goto('gui/usage#无线-portal');
  await expect(page.locator('[id="无线-portal"]')).toBeVisible();
  await page.reload();
  await expect(page.locator('[id="无线-portal"]')).toBeVisible();
  for (const target of ['desktop', 'overview']) {
    await page.goto(target);
    await expect(page.locator('.vp-doc img[src*="/badges/"]')).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  }
  await page.goto('screenshots');
  const screenshot = page.locator('.vp-doc img[src*="/images/"]').first();
  await expect(screenshot).toBeVisible();
  expect(await screenshot.evaluate((image: HTMLImageElement) => image.naturalWidth)).toBeGreaterThan(0);
  const original = page.getByRole('link', { name: '查看原图', exact: true }).first();
  const imageUrl = await original.getAttribute('href');
  await original.click();
  await expect(page).toHaveURL(new RegExp(imageUrl!.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$'));
  expect((await page.request.get(page.url())).headers()['content-type']).toContain('image/');
});

test('mobile documentation keeps navigation when JavaScript is disabled', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:4174/drcom4scut/gui/windows');
  const navigation = page.getByRole('navigation', { name: '帮助快捷导航' });
  await expect(navigation).toBeVisible();
  await navigation.getByRole('link', { name: '完整帮助目录' }).click();
  await expect(page).toHaveURL(/\/help$/);
  await expect(page.locator('h1')).toHaveText('帮助中心');
  await context.close();
});

test('update help connects desktop instructions with the core commands', async ({ page }) => {
  await page.goto('help');
  await page.getByRole('link', { name: '在窗口中更新图形界面或核心', exact: true }).click();
  await expect(page).toHaveURL(/\/gui\/update$/);
  await expect(page.locator('.vp-doc')).toContainText('检查核心更新');
  await page.getByRole('link', { name: '核心更新命令与自动提醒设置', exact: true }).click();
  await expect(page).toHaveURL(/\/guide\/update$/);
  await expect(page.locator('.vp-doc')).toContainText('--check-update');
  await expect(page.locator('.vp-doc')).toContainText('--no-update-check');
  await page.getByRole('link', { name: '更新设置', exact: true }).click();
  await expect.poll(() => decodeURI(page.url())).toMatch(/\/guide\/configuration#更新设置$/);
  await expect(page.locator('[id="更新设置"]')).toBeVisible();
});
