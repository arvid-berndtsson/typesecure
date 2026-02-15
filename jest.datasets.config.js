const base = require("./jest.config.js");

module.exports = {
  ...base,
  reporters: ["default", "<rootDir>/tests/datasets/dataset-reporter.cjs"],
};
