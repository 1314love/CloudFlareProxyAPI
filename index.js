/**
 * CloudFlareProxyAPI v7.0
 * URL 路径式多协议代理转发器
 *
 * 运行平台：Cloudflare Workers
 * 支持协议：HTTP, HTTPS, WebSocket
 *
 * Compatibility Date: 2025-04-01
 * Compatibility Flags: nodejs_compat
 */

// ============================================================================
// 配置常量
// ============================================================================

const CONFIG = Object.freeze({
  // 超时时间（毫秒）
  TIMEOUT_MS: 30_000,

  // 支持的协议
  PROTOCOLS: {
    HTTP: 'http:',
    HTTPS: 'https:',
    WS: 'ws:',
    WSS: 'wss:'
  },

  // 安全规则
  SECURITY: {
    BLOCKED_IP_PATTERNS: [
      /^127\./, /^0\.0\.0\.0$/, /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./,
      /^169\.254\./, /^::1$/, /^fc00::/i, /^fe80::/i, /^::ffff:/i
    ],
    BLOCKED_COOKIE_PREFIXES: ['__cf', 'cf_'],
    BLOCKED_COOKIE_KEYWORDS: ['cloudflare'],
    BLOCKED_HEADERS: new Set([
      'host', 'content-length', 'connection', 'upgrade',
      'sec-websocket-key', 'sec-websocket-version', 'te', 'keep-alive'
    ]),
    BLOCKED_HEADER_PREFIXES: ['cf-', 'x-forwarded-']
  },

  // 预编译正则表达式
  REGEX: {
    PROTOCOL: /^https?:\/\//i,
    WEBSOCKET_PROTOCOL: /^wss?:\/\//i,
    IP_ADDRESS: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    PORT: /:(\d+)(?:\/|$)/,
    SLASHES: /^\/+/,
    HTML_ATTR: /((href|src|action|data|formaction)\s*=\s*["'])\/([^"']+)(["'])/g,
    CSS_URL: /url\(\s*["']?\/(?!\/)([^"')]+)\s*["']?\)/g,
    JS_FETCH: /(fetch\(\s*["'])\/(?!\/)([^"']+)(["'])/g,
    JS_XHR: /\.open\(\s*(["'][^"']+["']\s*,\s*["'])\/(?!\/)([^"']+)(["'])/g
  },

  // 功能开关
  FEATURES: {
    ENABLE_STREAMING: true,
    ENABLE_CACHE: false,
    ENABLE_LOGGING: true
  }
});

// ============================================================================
// 工具函数
// ============================================================================

/**
 * 日志工具类
 */
const Logger = {
  info(...args) {
    if (CONFIG.FEATURES.ENABLE_LOGGING) {
      console.log('[INFO]', ...args);
    }
  },

  warn(...args) {
    if (CONFIG.FEATURES.ENABLE_LOGGING) {
      console.warn('[WARN]', ...args);
    }
  },

  error(...args) {
    if (CONFIG.FEATURES.ENABLE_LOGGING) {
      console.error('[ERROR]', ...args);
    }
  }
};

/**
 * 生成唯一请求 ID
 */
function generateRequestId() {
  return typeof crypto?.randomUUID === 'function'
    ? `req_${crypto.randomUUID()}`
    : `req_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * 性能计时器
 */
class PerformanceTimer {
  constructor() {
    this.startTime = performance.now();
  }

  elapsed() {
    return (performance.now() - this.startTime).toFixed(2);
  }
}

// ============================================================================
// URL 处理函数
// ============================================================================

/**
 * URL 处理 - 解析、标准化、验证
 */
class UrlHandler {
  /**
   * 解码 URL 路径
   * @param {string} pathname - URL 路径名
   * @returns {string} 解码后的路径
   */
  static decodePath(pathname) {
    try {
      return decodeURIComponent(pathname.slice(1));
    } catch {
      return pathname.slice(1);
    }
  }

  /**
   * 检测协议类型
   * @param {string} urlStr - URL 字符串
   * @returns {{type: string, protocol: string}} 协议信息
   */
  static detectProtocol(urlStr) {
    if (CONFIG.REGEX.WEBSOCKET_PROTOCOL.test(urlStr)) {
      return { type: 'websocket', protocol: urlStr.startsWith('wss') ? 'wss:' : 'ws:' };
    }
    if (CONFIG.REGEX.PROTOCOL.test(urlStr)) {
      return { type: 'http', protocol: urlStr.startsWith('https') ? 'https:' : 'http:' };
    }
    return { type: 'http', protocol: 'https:' };
  }

  /**
   * 标准化 URL
   * @param {string} urlStr - URL 字符串
   * @param {string} defaultProtocol - 默认协议
   * @returns {string} 标准化后的 URL
   */
  static normalize(urlStr, defaultProtocol = 'https:') {
    const normalized = urlStr.replace(CONFIG.REGEX.SLASHES, '');

    if (CONFIG.REGEX.PROTOCOL.test(normalized) || CONFIG.REGEX.WEBSOCKET_PROTOCOL.test(normalized)) {
      return normalized;
    }

    // 自动选择协议
    const protocol = this.selectProtocol(normalized, defaultProtocol);
    return `${protocol}//${normalized}`;
  }

  /**
   * 根据域名或端口选择协议
   * @param {string} urlStr - URL 字符串
   * @param {string} defaultProtocol - 默认协议
   * @returns {string} 协议
   */
  static selectProtocol(urlStr, defaultProtocol) {
    if (CONFIG.REGEX.IP_ADDRESS.test(urlStr)) return 'http:';

    const portMatch = urlStr.match(CONFIG.REGEX.PORT);
    if (portMatch) {
      const port = parseInt(portMatch[1], 10);
      if ([443, 8443].includes(port)) return 'https:';
      if ([80, 8080, 8000, 3000].includes(port)) return 'http:';
    }

    return defaultProtocol;
  }

  /**
   * 验证 URL（SSRF 防护）
   * @param {string} urlString - URL 字符串
   * @returns {{valid: boolean, error?: string}} 验证结果
   */
  static validate(urlString) {
    try {
      const url = new URL(urlString);

      // 检查协议白名单
      if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) {
        return { valid: false, error: '不支持的协议' };
      }

      const hostname = url.hostname.toLowerCase();

      // 阻止 localhost
      if (hostname === 'localhost') {
        return { valid: false, error: '不允许访问 localhost' };
      }

      // 检查内网 IP
      for (const pattern of CONFIG.SECURITY.BLOCKED_IP_PATTERNS) {
        if (pattern.test(hostname)) {
          return { valid: false, error: '不允许访问内网地址' };
        }
      }

      // IPv6 地址检查
      if (hostname.startsWith('[')) {
        const ipv6 = hostname.replace(/\[\]/g, '');
        if (ipv6 === '::1' || ipv6.toLowerCase().startsWith('fc') || ipv6.toLowerCase().startsWith('fe80')) {
          return { valid: false, error: '不允许访问 IPv6 本地地址' };
        }
      }

      return { valid: true };
    } catch (error) {
      return { valid: false, error: `URL 格式错误：${error.message}` };
    }
  }
}

/**
 * 请求头处理 - Cookie 清理、头部过滤
 */
class HeaderHandler {
  /**
   * 构建代理请求头
   * @param {Headers} originalHeaders - 原始请求头
   * @param {URL} clientUrl - 客户端 URL
   * @returns {Headers} 新的请求头
   */
  static buildProxyHeaders(originalHeaders, clientUrl) {
    const newHeaders = new Headers();

    // 处理 Cookie
    const cookie = originalHeaders.get('cookie');
    if (cookie) {
      const cleaned = this.cleanCookie(cookie);
      if (cleaned) newHeaders.set('cookie', cleaned);
    }

    // 复制其他请求头
    for (const [name, value] of originalHeaders.entries()) {
      const lower = name.toLowerCase();
      if (this.shouldBlockHeader(lower)) continue;
      newHeaders.set(name, value);
    }

    // 添加转发标识
    this.addForwardingHeaders(newHeaders, originalHeaders, clientUrl);

    return newHeaders;
  }

  /**
   * 清理 Cookie（过滤 Cloudflare 相关 Cookie）
   * @param {string} cookieString - Cookie 字符串
   * @returns {string|null} 清理后的 Cookie
   */
  static cleanCookie(cookieString) {
    if (!cookieString) return null;

    const validCookies = cookieString
      .split(';')
      .map(c => c.trim())
      .filter(Boolean)
      .filter(cookie => {
        const eqIndex = cookie.indexOf('=');
        if (eqIndex === -1) return false;

        const name = cookie.substring(0, eqIndex).trim();
        if (!name) return false;

        return !this.isBlockedCookie(name);
      });

    return validCookies.length > 0 ? validCookies.join('; ') : null;
  }

  /**
   * 检查 Cookie 是否被阻止
   * @param {string} name - Cookie 名称
   * @returns {boolean} 是否被阻止
   */
  static isBlockedCookie(name) {
    const lowerName = name.toLowerCase();
    return CONFIG.SECURITY.BLOCKED_COOKIE_PREFIXES.some(prefix => name.startsWith(prefix)) ||
           CONFIG.SECURITY.BLOCKED_COOKIE_KEYWORDS.some(kw => lowerName.includes(kw));
  }

  /**
   * 检查请求头是否被阻止
   * @param {string} name - 请求头名称
   * @returns {boolean} 是否被阻止
   */
  static shouldBlockHeader(name) {
    return CONFIG.SECURITY.BLOCKED_HEADERS.has(name) ||
           CONFIG.SECURITY.BLOCKED_HEADER_PREFIXES.some(prefix => name.startsWith(prefix));
  }

  /**
   * 添加转发信息头部
   * @param {Headers} headers - 请求头对象
   * @param {Headers} originalHeaders - 原始请求头
   * @param {URL} clientUrl - 客户端 URL
   */
  static addForwardingHeaders(headers, originalHeaders, clientUrl) {
    const clientIP = originalHeaders.get('CF-Connecting-IP');
    if (clientIP) headers.set('X-Forwarded-For', clientIP);
    headers.set('X-Forwarded-Proto', clientUrl.protocol.replace(':', ''));
    headers.set('X-Forwarded-Host', clientUrl.host);
  }
}

/**
 * HTML 内容重写 - 修正相对路径
 */
class HtmlRewriter {
  /**
   * 重写 HTML 中的相对路径
   * @param {string} html - HTML 内容
   * @param {string} targetUrl - 目标 URL
   * @param {URL} clientUrl - 客户端 URL
   * @returns {string} 重写后的 HTML
   */
  static rewrite(html, targetUrl, clientUrl) {
    try {
      const targetOrigin = new URL(targetUrl).origin;
      const prefix = `${clientUrl.protocol}//${clientUrl.host}/${targetOrigin}/`;

      return html
        .replace(CONFIG.REGEX.HTML_ATTR, `$1${prefix}$3$4`)
        .replace(CONFIG.REGEX.CSS_URL, `url("${prefix}$1")`)
        .replace(CONFIG.REGEX.JS_FETCH, `$1${prefix}$3$4`)
        .replace(CONFIG.REGEX.JS_XHR, `.open($1, "${prefix}$3$4`);
    } catch (error) {
      Logger.warn('HTML rewrite failed:', error.message);
      return html;
    }
  }
}

// ============================================================================
// 协议处理器
// ============================================================================

/**
 * 协议处理器基类
 */
class ProtocolStrategy {
  /**
   * 判断是否可以处理该协议
   * @param {{type: string, protocol: string}} protocolInfo - 协议信息
   * @returns {boolean} 是否可以处理
   */
  canHandle(protocolInfo) {
    throw new Error('Must implement canHandle');
  }

  /**
   * 处理请求
   * @param {Request} request - 请求对象
   * @param {string} targetUrl - 目标 URL
   * @param {Object} context - 上下文对象
   * @returns {Promise<Response>} 响应对象
   */
  async handle(request, targetUrl, context) {
    throw new Error('Must implement handle');
  }
}

/**
 * HTTP/HTTPS协议处理器
 */
class HttpStrategy extends ProtocolStrategy {
  canHandle(protocolInfo) {
    return protocolInfo.type === 'http';
  }

  /**
   * HTTP 请求处理
   * @param {Request} request - 请求对象
   * @param {string} targetUrl - 目标 URL
   * @param {{timer: PerformanceTimer, requestId: string, clientUrl: URL}} context - 上下文对象
   * @returns {Promise<Response>} 响应对象
   */
  async handle(request, targetUrl, context) {
    // 构建请求
    const headers = HeaderHandler.buildProxyHeaders(request.headers, context.clientUrl);
    const proxyRequest = new Request(targetUrl, {
      method: request.method,
      headers,
      body: request.body,
      redirect: 'manual',
      duplex: 'half'
    });

    // 执行请求
    const response = await this.fetchWithTimeout(proxyRequest, CONFIG.TIMEOUT_MS);

    // 处理响应
    return this.processResponse(response, targetUrl, context);
  }

  /**
   * 带超时的 Fetch 请求
   * @param {Request} request - 请求对象
   * @param {number} timeout - 超时时间（毫秒）
   * @returns {Promise<Response>} 响应对象
   */
  async fetchWithTimeout(request, timeout) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(request, { signal: controller.signal });
      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new Error(`请求超时（>${timeout / 1000}秒）`);
      }
      throw error;
    }
  }

  /**
   * 处理响应（重定向、HTML 重写等）
   * @param {Response} response - 响应对象
   * @param {string} targetUrl - 目标 URL
   * @param {{timer: PerformanceTimer, requestId: string, clientUrl: URL}} context - 上下文对象
   * @returns {Response|Promise<Response>} 响应对象
   */
  processResponse(response, targetUrl, context) {
    // 处理 HTTP 重定向
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      return this.handleRedirect(response, targetUrl);
    }

    // 处理 HTML 内容（重写相对路径）
    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('text/html')) {
      return this.handleHtmlResponse(response, targetUrl, context);
    }

    // 其他类型直接返回
    return this.createResponse(response, context);
  }

  /**
   * 处理 HTTP 重定向响应
   * @param {Response} response - 响应对象
   * @param {string} targetUrl - 目标 URL
   * @returns {Response} 重定向响应
   */
  handleRedirect(response, targetUrl) {
    const location = response.headers.get('location');
    if (!location) {
      Logger.warn('Redirect without Location header');
      return response;
    }

    try {
      const absoluteLocation = new URL(location, targetUrl);
      const encodedLocation = '/' + encodeURIComponent(absoluteLocation.toString());

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: { ...response.headers, 'Location': encodedLocation }
      });
    } catch (error) {
      Logger.error('Failed to process redirect:', error.message);
      return response;
    }
  }

  /**
   * 处理 HTML 响应并重写相对路径
   * @param {Response} response - 响应对象
   * @param {string} targetUrl - 目标 URL
   * @param {{timer: PerformanceTimer, requestId: string, clientUrl: URL}} context - 上下文对象
   * @returns {Promise<Response>} 响应对象
   */
  handleHtmlResponse(response, targetUrl, context) {
    return response.text().then(html => {
      const rewritten = HtmlRewriter.rewrite(html, targetUrl, context.clientUrl);
      return this.createResponse(response, context, rewritten);
    });
  }

  /**
   * 创建标准响应
   * @param {Response} response - 原始响应
   * @param {{timer: PerformanceTimer, requestId: string, clientUrl: URL}} context - 上下文对象
   * @param {string} [body] - 响应体（可选，用于重写后的 HTML）
   * @returns {Response} 新响应
   */
  createResponse(response, context, body) {
    const newResponse = new Response(body !== undefined ? body : response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });

    this.addStandardHeaders(newResponse.headers);
    this.addPerformanceHeaders(newResponse.headers, context);

    return newResponse;
  }

  /**
   * 添加标准响应头（CORS、缓存控制等）
   * @param {Headers} headers - 响应头对象
   */
  addStandardHeaders(headers) {
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    headers.set('Pragma', 'no-cache');
    headers.set('Expires', '0');
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin, Cookie');
    headers.set('Access-Control-Max-Age', '86400');
    headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Set-Cookie');
  }

  /**
   * 添加性能监控信息到响应头
   * @param {Headers} headers - 响应头对象
   * @param {{timer: PerformanceTimer, requestId: string, clientUrl: URL}} context - 上下文对象
   */
  addPerformanceHeaders(headers, context) {
    headers.set('X-Proxy-Request-ID', context.requestId);
    headers.set('X-Proxy-Duration', `${context.timer.elapsed()}ms`);
    headers.set('X-Proxy-Timestamp', new Date().toISOString());
  }
}

/**
 * WebSocket协议处理器
 */
class WebSocketStrategy extends ProtocolStrategy {
  canHandle(protocolInfo) {
    return protocolInfo.type === 'websocket';
  }

  /**
   * 处理 WebSocket 连接请求
   * @param {Request} request - 请求对象
   * @param {string} targetWsUrl - 目标 WebSocket URL
   * @param {{timer: PerformanceTimer, requestId: string, clientUrl: URL}} context - 上下文对象
   * @returns {Promise<Response>} WebSocket 响应
   */
  async handle(request, targetWsUrl, context) {
    try {
      // 连接到目标 WebSocket 服务器
      const response = await fetch(targetWsUrl, {
        headers: {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade'
        },
        signal: request.signal
      });

      const serverWebSocket = response.webSocket;
      if (!serverWebSocket) {
        throw new Error('Server did not accept WebSocket connection');
      }

      // 创建 WebSocket Pair
      const webSocketPair = new WebSocketPair();
      const [client, server] = webSocketPair;
      server.accept();

      // 桥接客户端和服务器
      this.bridgeWebSockets(client, serverWebSocket, context.requestId);

      return new Response(null, {
        status: 101,
        webSocket: client
      });
    } catch (error) {
      throw new Error(`WebSocket proxy failed: ${error.message}`);
    }
  }

  /**
   * 桥接客户端和服务端 WebSocket
   * @param {WebSocket} client - 客户端 WebSocket
   * @param {WebSocket} server - 服务端 WebSocket
   * @param {string} requestId - 请求 ID（用于日志）
   */
  bridgeWebSockets(client, server, requestId) {
    // Client -> Server
    client.addEventListener('message', (event) => {
      if (server.readyState === WebSocket.OPEN) {
        server.send(event.data);
      }
    });

    // Server -> Client
    server.addEventListener('message', (event) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(event.data);
      }
    });

    // Handle close
    client.addEventListener('close', (event) => {
      if (server.readyState === WebSocket.OPEN) {
        server.close(event.code, event.reason);
      }
    });

    server.addEventListener('close', (event) => {
      if (client.readyState === WebSocket.OPEN) {
        client.close(event.code, event.reason);
      }
    });

    // Handle errors
    client.addEventListener('error', () => Logger.error(`[${requestId}] Client WebSocket error`));
    server.addEventListener('error', () => Logger.error(`[${requestId}] Server WebSocket error`));
  }
}

// ============================================================================
// 请求处理主逻辑
// ============================================================================

/**
 * 请求处理器 - 主入口
 */
class RequestHandler {
  constructor() {
    // 注册策略
    this.strategies = [
      new WebSocketStrategy(),
      new HttpStrategy()
    ];
  }

  /**
   * 处理 HTTP/HTTPS 请求
   * @param {Request} request - 请求对象
   * @returns {Promise<Response>} 响应对象
   */
  async handleRequest(request) {
    const timer = new PerformanceTimer();
    const requestId = generateRequestId();
    const context = { timer, requestId, clientUrl: new URL(request.url) };

    try {
      // 1. 解码目标 URL
      const encodedTarget = UrlHandler.decodePath(context.clientUrl.pathname);

      // 2. 根路径返回 API 信息
      if (!encodedTarget) {
        return ResponseFactory.apiInfo(timer, requestId);
      }

      // 3. 检测和标准化协议
      const protocolInfo = UrlHandler.detectProtocol(encodedTarget);
      const targetUrl = UrlHandler.normalize(encodedTarget, context.clientUrl.protocol);

      // 4. 验证 URL（SSRF 防护）
      const validation = UrlHandler.validate(targetUrl);
      if (!validation.valid) {
        return ResponseFactory.error('INVALID_TARGET', validation.error, 400, timer, requestId, { url: targetUrl });
      }

      // 5. 选择策略并处理
      const strategy = this.selectStrategy(protocolInfo);
      return await strategy.handle(request, targetUrl, context);

    } catch (error) {
      return ErrorHandler.handle(error, requestId, timer);
    }
  }

  /**
   * 根据协议类型选择处理器
   * @param {{type: string, protocol: string}} protocolInfo - 协议信息
   * @returns {ProtocolStrategy} 协议处理器
   */
  selectStrategy(protocolInfo) {
    const strategy = this.strategies.find(s => s.canHandle(protocolInfo));
    if (!strategy) {
      throw new Error(`Unsupported protocol: ${protocolInfo.type}`);
    }
    return strategy;
  }

  /**
   * 处理 WebSocket 连接事件
   * @param {Object} event - WebSocket 事件
   * @returns {Response} WebSocket 响应
   */
  handleWebSocket(event) {
    const { webSocket } = event;
    webSocket.accept();

    // Echo 服务示例
    webSocket.addEventListener('message', (message) => {
      webSocket.send(`Echo: ${message.data}`);
    });

    webSocket.addEventListener('close', () => Logger.info('WebSocket connection closed'));
    webSocket.addEventListener('error', (error) => Logger.error('WebSocket error:', error));

    return new Response(null, { status: 101, webSocket });
  }
}

/**
 * 响应工厂 - 创建标准响应和错误响应
 */
const ResponseFactory = {
  /**
   * 创建 API 信息响应
   * @param {PerformanceTimer} timer - 性能计时器
   * @param {string} requestId - 请求 ID
   * @returns {Response} JSON 响应
   */
  apiInfo(timer, requestId) {
    const data = {
      name: 'CloudFlareProxyAPI',
      version: '7.0.0',
      description: 'URL-based multi-protocol proxy forwarder',
      protocols: {
        http: 'HTTP/HTTPS',
        websocket: 'WebSocket'
      },
      usage: {
        format: '/<encoded_target_url>',
        examples: [
          '/api.github.com/users/octocat',
          '/https://example.com/path',
          '/ws/wss://echo.websocket.org'
        ]
      },
      features: [
        'Automatic protocol detection',
        'SSRF protection',
        'Cookie filtering',
        'HTML path rewriting',
        'WebSocket bridging',
        'Performance monitoring'
      ]
    };

    const response = new Response(JSON.stringify(data, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });

    this.addPerformanceHeaders(response.headers, timer, requestId);
    return response;
  },

  /**
   * 创建错误响应
   * @param {string} code - 错误代码
   * @param {string} message - 错误消息
   * @param {number} status - HTTP 状态码
   * @param {PerformanceTimer} timer - 性能计时器
   * @param {string} requestId - 请求 ID
   * @param {Object} [details={}] - 其他详情
   * @returns {Response} JSON 错误响应
   */
  error(code, message, status, timer, requestId, details = {}) {
    const data = {
      error: {
        code,
        message,
        timestamp: new Date().toISOString(),
        ...details
      }
    };

    const response = new Response(JSON.stringify(data, null, 2), {
      status,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });

    this.addPerformanceHeaders(response.headers, timer, requestId);
    return response;
  },

  /**
   * 添加性能监控信息到响应头
   * @param {Headers} headers - 响应头对象
   * @param {PerformanceTimer} timer - 性能计时器
   * @param {string} requestId - 请求 ID
   */
  addPerformanceHeaders(headers, timer, requestId) {
    headers.set('X-Proxy-Request-ID', requestId);
    headers.set('X-Proxy-Duration', `${timer.elapsed()}ms`);
    headers.set('X-Proxy-Timestamp', new Date().toISOString());
  }
};

/**
 * 错误处理器 - 统一处理异常
 */
const ErrorHandler = {
  /**
   * 处理异常并返回错误响应
   * @param {Error} error  - 异常对象
   * @param {string} requestId - 请求 ID
   * @param {PerformanceTimer} timer - 性能计时器
   * @returns {Response} 错误响应
   */
  handle(error, requestId, timer) {
    try {
      // 判断错误类型
      const errorCode = error.message.includes('超时') ? 'TIMEOUT' : 'PROXY_ERROR';
      const statusMap = {
        'INVALID_TARGET': 400,
        'TIMEOUT': 504,
        'PROXY_ERROR': 502
      };

      return ResponseFactory.error(
        errorCode,
        error.message,
        statusMap[errorCode] || 500,
        timer,
        requestId,
        { suggestion: errorCode === 'TIMEOUT' ? '请检查网络连接' : '请稍后重试' }
      );
    } catch (handleError) {
      Logger.error('Error in error handler:', handleError);
      return new Response(JSON.stringify({
        error: {
          code: 'INTERNAL_ERROR',
          message: '错误处理失败',
          originalError: error?.message || 'Unknown error'
        }
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      });
    }
  }
};

// ============================================================================
// 入口点 - Cloudflare Workers 事件监听
// ============================================================================

// 创建请求处理器实例
const handler = new RequestHandler();

// HTTP/HTTPS 请求处理
addEventListener('fetch', event => {
  event.respondWith(handler.handleRequest(event.request));
});

// WebSocket 连接处理
addEventListener('websocket', event => {
  event.respondWith(handler.handleWebSocket(event));
});
