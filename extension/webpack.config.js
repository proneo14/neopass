const path = require('path');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

const targetBrowser = process.env.TARGET_BROWSER || 'chrome';

const manifestMap = {
  chrome: 'manifest.chrome.json',
  edge: 'manifest.chrome.json', // Edge uses same MV3 manifest as Chrome
  firefox: 'manifest.firefox.json',
};

module.exports = {
  entry: {
    background: path.resolve(__dirname, 'src/background/service-worker.ts'),
    content: path.resolve(__dirname, 'src/content/content.ts'),
    'passkey-provider': path.resolve(__dirname, 'src/content/passkey-provider.ts'),
    popup: path.resolve(__dirname, 'src/popup/index.tsx'),
  },

  output: {
    path: path.resolve(__dirname, `dist/${targetBrowser}`),
    filename: '[name].js',
    clean: true,
  },

  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
  },

  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.css$/,
        use: [MiniCssExtractPlugin.loader, 'css-loader', 'postcss-loader'],
      },
    ],
  },

  plugins: [
    new MiniCssExtractPlugin({
      filename: '[name].css',
    }),

    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, 'src/popup/popup.html'),
      filename: 'popup.html',
      chunks: ['popup'],
    }),

    new CopyWebpackPlugin({
      patterns: [
        {
          from: path.resolve(__dirname, `src/${manifestMap[targetBrowser]}`),
          to: 'manifest.json',
        },
        {
          from: path.resolve(__dirname, 'src/icons'),
          to: 'icons',
          noErrorOnMissing: true,
        },
      ],
    }),
  ],

  devtool: 'cheap-module-source-map',

  optimization: {
    splitChunks: false, // Extensions need self-contained scripts
  },
};
