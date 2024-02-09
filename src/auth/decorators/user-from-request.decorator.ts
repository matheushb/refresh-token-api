import { createParamDecorator } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host';

export const UserFromRequest = createParamDecorator(
  (_, context: ExecutionContextHost) => {
    const request = context.switchToHttp().getRequest();
    return request.user;
  },
);
