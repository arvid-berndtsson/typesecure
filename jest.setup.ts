import "jest";
import {
  toBeClassified,
  toBeClassifiedAs,
  toAllowAction,
  toBeRedacted,
  toBeRedactedAs,
  type TypesecureMatchers,
} from "./src/testing";

// Extend Jest matchers
declare global {
  namespace jest {
    interface Matchers<R> extends TypesecureMatchers<R> {}
  }
}

// Register custom matchers
expect.extend({
  toBeClassified,
  toBeClassifiedAs,
  toAllowAction,
  toBeRedacted,
  toBeRedactedAs,
});
