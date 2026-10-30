module.exports = {
   coverageProvider: "v8",
   modulePaths: ["<rootDir>"],
   roots: ["<rootDir>"],
   testEnvironment: "node",
   testMatch: ["**/*.(steps|test).(ts|js)"],
   transform: {
      "\\.ts$": ["ts-jest"],
   },
};
