import request from 'supertest';
import type { Express } from 'express';

/**
 * A wrapper around supertest's request that automatically adds the X-Layer: core header.
 */
export const coreRequest = (app: Express) => {
  const agent = request(app);
  
  const handler: ProxyHandler<any> = {
    get(target, prop) {
      const value = target[prop];
      if (typeof value === 'function' && ['get', 'post', 'put', 'delete', 'patch', 'head'].includes(prop as string)) {
        return (...args: any[]) => value.apply(target, args).set('X-Layer', 'core');
      }
      return value;
    }
  };

  return new Proxy(agent, handler);
};
