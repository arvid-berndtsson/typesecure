# NestJS Integration Example

This example demonstrates how to use typesecure with NestJS.

## Features

- **Interceptors**: Automatic response redaction and validation
- **DTO Classification**: Helper to classify DTO fields
- **Policy Enforcement**: Validates data before network operations

## Installation

```bash
npm install @nestjs/common @nestjs/core typesecure
```

## Basic Usage

### 1. Create an Interceptor

```typescript
import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from "@nestjs/common";
import { Observable } from "rxjs";
import { map } from "rxjs/operators";
import { defaultPolicy, assertAllowed, redact } from "typesecure";

@Injectable()
export class SafeResponseInterceptor implements NestInterceptor {
  private policy = defaultPolicy();

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      map((data) => {
        assertAllowed(this.policy, "network", data);
        return redact(data);
      }),
    );
  }
}
```

### 2. Apply to Controller

```typescript
import { Controller, Post, UseInterceptors } from "@nestjs/common";
import { SafeResponseInterceptor } from "./safe-response.interceptor";
import { piiText, publicText } from "typesecure";

@Controller("users")
@UseInterceptors(new SafeResponseInterceptor())
export class UsersController {
  @Post()
  create(@Body() body: { email: string }) {
    const email = piiText(body.email);
    return {
      message: publicText("User created"),
      email, // Will be redacted by interceptor
    };
  }
}
```

### 3. Global Interceptor

```typescript
// app.module.ts
import { Module } from "@nestjs/common";
import { APP_INTERCEPTOR } from "@nestjs/core";
import { SafeResponseInterceptor } from "./safe-response.interceptor";

@Module({
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: SafeResponseInterceptor,
    },
  ],
})
export class AppModule {}
```

## DTO Classification

```typescript
import { classifyDto } from "./decorators";

class CreateUserDto {
  email: string;
  password: string;
}

const classified = classifyDto(dto, {
  email: "pii",
  password: "secret",
});
```

## Running the Example

```bash
# Install dependencies
npm install

# Run NestJS app
npm run start:dev
```

## Note

This is a simplified example. A full NestJS integration would include:
- Custom decorators with metadata
- Pipes for automatic classification
- Guards for policy enforcement
- Proper dependency injection
