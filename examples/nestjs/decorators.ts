/**
 * NestJS decorators and interceptors for typesecure.
 *
 * @example
 * ```ts
 * import { Controller, Post, Body } from "@nestjs/common";
 * import { Classify, SafeResponse } from "./decorators";
 *
 * @Controller("users")
 * export class UsersController {
 *   @Post()
 *   @SafeResponse()
 *   create(@Body() @Classify("pii") body: { email: string }) {
 *     return { email: piiText(body.email) };
 *   }
 * }
 * ```
 */

import {
  type Policy,
  defaultPolicy,
  assertAllowed,
  redact,
  type DataClassification,
  piiText,
  secretText,
  token,
  credential,
  publicText,
} from "typesecure";
import type { ExecutionContext, CallHandler } from "@nestjs/common";
import { Injectable, NestInterceptor } from "@nestjs/common";
import { Observable } from "rxjs";
import { map } from "rxjs/operators";

/**
 * Decorator to classify request body fields.
 * This is a placeholder - actual implementation would require more NestJS integration.
 *
 * @param classification - Classification kind to apply
 */
export function Classify(
  classification: DataClassification,
): ParameterDecorator {
  return (target: unknown, propertyKey: string | symbol, parameterIndex: number) => {
    // In a real implementation, you'd store metadata here
    // and use it in an interceptor to classify the data
  };
}

/**
 * Interceptor to automatically redact and validate responses.
 */
@Injectable()
export class SafeResponseInterceptor implements NestInterceptor {
  constructor(private readonly policy: Policy = defaultPolicy()) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      map((data) => {
        // Validate response
        try {
          assertAllowed(this.policy, "network", data);
        } catch (error) {
          throw new Error(`Policy violation: ${error instanceof Error ? error.message : "unknown"}`);
        }

        // Redact response
        return redact(data);
      }),
    );
  }
}

/**
 * Decorator factory to apply SafeResponseInterceptor.
 * Usage: @SafeResponse()
 */
export function SafeResponse(): ClassDecorator & MethodDecorator {
  return (target: unknown, propertyKey?: string | symbol, descriptor?: PropertyDescriptor) => {
    // In a real implementation, you'd use SetMetadata and apply the interceptor
    // This is a simplified example
  };
}

/**
 * Helper to classify DTO fields.
 *
 * @example
 * ```ts
 * class CreateUserDto {
 *   email: string;
 *   password: string;
 * }
 *
 * const classified = classifyDto(CreateUserDto, {
 *   email: "pii",
 *   password: "secret",
 * }, dto);
 * ```
 */
export function classifyDto<T extends Record<string, unknown>>(
  dto: T,
  classifications: Partial<Record<keyof T, DataClassification>>,
): T {
  const result = { ...dto };
  for (const [key, classification] of Object.entries(classifications)) {
    const value = dto[key];
    if (typeof value === "string" && value) {
      switch (classification) {
        case "pii":
          (result as Record<string, unknown>)[key] = piiText(value);
          break;
        case "secret":
          (result as Record<string, unknown>)[key] = secretText(value);
          break;
        case "token":
          (result as Record<string, unknown>)[key] = token(value);
          break;
        case "credential":
          (result as Record<string, unknown>)[key] = credential(value);
          break;
        case "public":
          (result as Record<string, unknown>)[key] = publicText(value);
          break;
      }
    }
  }
  return result;
}
