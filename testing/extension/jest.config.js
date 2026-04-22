const path = require('path');

const extensionDir = path.resolve(__dirname, '../../extension');

/** @type {import('jest').Config} */
module.exports = {
  testMatch: ['<rootDir>/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': [
      path.join(extensionDir, 'node_modules/ts-jest'),
      { tsconfig: path.join(extensionDir, 'tsconfig.json') },
    ],
  },
  testEnvironment: path.join(extensionDir, 'node_modules/jest-environment-jsdom'),
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  moduleDirectories: ['node_modules', path.join(extensionDir, 'node_modules')],
  modulePaths: [extensionDir],
};
