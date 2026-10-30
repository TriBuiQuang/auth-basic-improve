// eslint-disable-next-line @typescript-eslint/no-require-imports
const tseslint = require("typescript-eslint");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const importPlugin = require("eslint-plugin-import");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const prettierPlugin = require("eslint-plugin-prettier/recommended");

module.exports = tseslint.config(
  { ignores: ["dist/", "node_modules/"] },
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts", "**/*.tsx"],
    plugins: {
      import: importPlugin,
      "@typescript-eslint": tseslint.plugin,
    },
    languageOptions: {
      globals: {
        describe: "readonly",
        it: "readonly",
        expect: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
        beforeAll: "readonly",
        afterAll: "readonly",
        jest: "readonly",
      },
    },
    settings: {
      "import/extensions": [".js", ".jsx", ".ts", ".tsx"],
      "import/parsers": { "@typescript-eslint/parser": [".ts", ".tsx"] },
      "import/resolver": {
        node: { extensions: [".js", ".jsx", ".ts", ".tsx"] },
        typescript: {},
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": ["warn"],
      "import/extensions": ["error", "ignorePackages", { ts: "never" }],
      "import/no-extraneous-dependencies": [0],
      "import/no-named-as-default-member": 0,
      "import/no-unresolved": [2, { amd: true, commonjs: true }],
      "import/order": "off",
      "import/prefer-default-export": 0,
      "no-console": [1, { allow: ["error", "info"] }],
      "no-promise-executor-return": ["warn"],
      "no-shadow": 0,
      "no-unused-vars": 0,
      "prettier/prettier": ["error"],
      quotes: [2, "double", { allowTemplateLiterals: true, avoidEscape: true }],
      "sort-keys": [1, "asc", { caseSensitive: true, natural: true }],
    },
  },
  prettierPlugin,
);
