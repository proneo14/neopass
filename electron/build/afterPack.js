/**
 * electron-builder afterPack hook.
 * Registers the native messaging host for browser extensions after packaging.
 */
const path = require('path');
const { execFileSync } = require('child_process');
const fs = require('fs');

exports.default = async function afterPack(context) {
  const platform = context.electronPlatformName;
  const appDir = context.appOutDir;
  const resourcesDir = path.join(appDir, 'resources');

  console.log(`[afterPack] platform=${platform}, appDir=${appDir}`);

  // The native host binary is included in extraResources/bin/
  const ext = platform === 'win32' ? '.exe' : '';
  const nativeHostBinary = path.join(resourcesDir, 'bin', `neopass-native-host${ext}`);

  if (!fs.existsSync(nativeHostBinary)) {
    console.warn(`[afterPack] native host binary not found at ${nativeHostBinary}, skipping registration`);
    return;
  }

  // Make executable on Unix
  if (platform !== 'win32') {
    try {
      fs.chmodSync(nativeHostBinary, 0o755);
    } catch (err) {
      console.warn(`[afterPack] chmod failed: ${err.message}`);
    }
  }

  console.log(`[afterPack] native host binary found: ${nativeHostBinary}`);
};
