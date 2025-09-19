import { Controller, Get } from '@nestjs/common';
import type { Cache } from 'cache-manager';
import { Inject } from '@nestjs/common';

@Controller('redis-test')
export class RedisTestController {
  constructor(@Inject('CACHE_MANAGER') private cache: Cache) {}

  @Get('ping')
  async testRedis() {
    await this.cache.set('redis_test_key', 'Redis is working!', 10);
    const result = await this.cache.get('redis_test_key');
    return { result };
  }
}
