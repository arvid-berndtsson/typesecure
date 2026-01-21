/**
 * NestJS example using typesecure.
 *
 * This is a conceptual example. Full NestJS integration would require:
 * - Custom decorators with proper metadata
 * - Interceptors with dependency injection
 * - Guards for policy enforcement
 * - Pipes for automatic classification
 */

// users.controller.ts
/*
import { Controller, Post, Get, Body, Param, UseInterceptors } from "@nestjs/common";
import { SafeResponseInterceptor, classifyDto } from "./decorators";
import { piiText, publicText, defaultPolicy, assertAllowed } from "typesecure";

const policy = defaultPolicy();

@Controller("users")
@UseInterceptors(new SafeResponseInterceptor(policy))
export class UsersController {
  @Post()
  create(@Body() body: { email: string; name: string; password: string }) {
    // Classify DTO
    const classified = classifyDto(body, {
      email: "pii",
      name: "pii",
      password: "secret",
    });

    // Validate storage
    assertAllowed(policy, "storage", classified);

    // Response will be automatically redacted by interceptor
    return {
      message: publicText("User created"),
      userId: 123,
      email: classified.email,
      name: classified.name,
    };
  }

  @Get(":id")
  findOne(@Param("id") id: string) {
    // Response will be automatically redacted
    return {
      id,
      email: piiText("user@example.com"),
      name: piiText("John Doe"),
    };
  }
}
*/

// app.module.ts
/*
import { Module } from "@nestjs/common";
import { APP_INTERCEPTOR } from "@nestjs/core";
import { UsersController } from "./users.controller";
import { SafeResponseInterceptor } from "./decorators";
import { defaultPolicy } from "typesecure";

@Module({
  controllers: [UsersController],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: SafeResponseInterceptor,
      useValue: new SafeResponseInterceptor(defaultPolicy()),
    },
  ],
})
export class AppModule {}
*/

export {};
